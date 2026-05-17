package httpadapter

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rcooler/aegrail/hub/internal/domain"
	hubapp "github.com/rcooler/aegrail/hub/internal/hub"
)

func TestHubRouterManagesUsersAndTOTPEnrollment(t *testing.T) {
	users := newHTTPTestHubUserRepository()
	router := NewHubRouter(
		domain.AppMeta{Name: "Aegrail", Binary: "aegrail", Version: "test"},
		hubapp.New(hubapp.Dependencies{Users: users, UserSecretKey: "local-test-secret"}),
		HubOptions{},
	)

	createRequest := httptest.NewRequest(http.MethodPost, "/api/v1/access/users", bytes.NewBufferString(`{
		"email":"Admin@Example.test",
		"display_name":"Admin User",
		"access_level":"admin",
		"password":"correct horse battery staple",
		"status":"active",
		"two_factor_required":true
	}`))
	createResponse := httptest.NewRecorder()
	router.ServeHTTP(createResponse, createRequest)
	if createResponse.Code != http.StatusCreated {
		t.Fatalf("create status = %d body = %s", createResponse.Code, createResponse.Body.String())
	}
	var createBody struct {
		User struct {
			ID                string `json:"id"`
			Email             string `json:"email"`
			AccessLevel       string `json:"access_level"`
			TwoFactorRequired bool   `json:"two_factor_required"`
			TwoFactorEnabled  bool   `json:"two_factor_enabled"`
		} `json:"user"`
	}
	if err := json.NewDecoder(createResponse.Body).Decode(&createBody); err != nil {
		t.Fatalf("Decode create returned error: %v", err)
	}
	if createBody.User.Email != "admin@example.test" || createBody.User.AccessLevel != "owner" || !createBody.User.TwoFactorRequired || createBody.User.TwoFactorEnabled {
		t.Fatalf("created user = %#v, want normalized bootstrap owner requiring unenrolled 2FA", createBody.User)
	}

	loginRequest := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString(`{
		"email":"admin@example.test",
		"password":"correct horse battery staple"
	}`))
	loginResponse := httptest.NewRecorder()
	router.ServeHTTP(loginResponse, loginRequest)
	if loginResponse.Code != http.StatusOK {
		t.Fatalf("login status = %d body = %s", loginResponse.Code, loginResponse.Body.String())
	}
	var loginBody struct {
		CSRFToken         string `json:"csrf_token"`
		DashboardReady    bool   `json:"dashboard_ready"`
		TOTPSetupRequired bool   `json:"totp_setup_required"`
	}
	if err := json.NewDecoder(loginResponse.Body).Decode(&loginBody); err != nil {
		t.Fatalf("Decode login returned error: %v", err)
	}
	if loginBody.CSRFToken == "" || loginBody.DashboardReady || !loginBody.TOTPSetupRequired {
		t.Fatalf("login body = %#v, want setup-only session with CSRF token", loginBody)
	}
	cookies := loginResponse.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatalf("login did not set a session cookie")
	}

	blockedListRequest := httptest.NewRequest(http.MethodGet, "/api/v1/access/users", nil)
	blockedListRequest.AddCookie(cookies[0])
	blockedListResponse := httptest.NewRecorder()
	router.ServeHTTP(blockedListResponse, blockedListRequest)
	if blockedListResponse.Code != http.StatusForbidden {
		t.Fatalf("unenrolled list status = %d body = %s", blockedListResponse.Code, blockedListResponse.Body.String())
	}

	startRequest := httptest.NewRequest(http.MethodPost, "/api/v1/auth/totp/start", bytes.NewBufferString(`{"issuer":"Aegrail Local"}`))
	addDashboardAuth(startRequest, cookies[0], loginBody.CSRFToken)
	startResponse := httptest.NewRecorder()
	router.ServeHTTP(startResponse, startRequest)
	if startResponse.Code != http.StatusCreated {
		t.Fatalf("totp start status = %d body = %s", startResponse.Code, startResponse.Body.String())
	}
	var startBody struct {
		User struct {
			TwoFactorEnabled bool `json:"two_factor_enabled"`
			TwoFactorPending bool `json:"two_factor_pending"`
		} `json:"user"`
		Enrollment struct {
			OTPAuthURL    string `json:"otpauth_url"`
			QRCodeDataURL string `json:"qr_code_data_url"`
			Secret        string `json:"secret"`
		} `json:"enrollment"`
	}
	if err := json.NewDecoder(startResponse.Body).Decode(&startBody); err != nil {
		t.Fatalf("Decode start returned error: %v", err)
	}
	if startBody.User.TwoFactorEnabled {
		t.Fatalf("2FA enabled before verify; flow regressed")
	}
	if !startBody.User.TwoFactorPending {
		t.Fatalf("2FA pending flag was not set after start")
	}
	if startBody.Enrollment.Secret == "" || !strings.Contains(startBody.Enrollment.OTPAuthURL, "otpauth://totp/") || !strings.Contains(startBody.Enrollment.QRCodeDataURL, "data:image/png;base64,") {
		t.Fatalf("enrollment payload = %#v, want secret, otpauth url, and QR data URL", startBody.Enrollment)
	}

	wrongVerifyRequest := httptest.NewRequest(http.MethodPost, "/api/v1/auth/totp/verify", bytes.NewBufferString(`{"code":"000000"}`))
	addDashboardAuth(wrongVerifyRequest, cookies[0], loginBody.CSRFToken)
	wrongVerifyResponse := httptest.NewRecorder()
	router.ServeHTTP(wrongVerifyResponse, wrongVerifyRequest)
	if wrongVerifyResponse.Code != http.StatusUnauthorized {
		t.Fatalf("wrong code status = %d body = %s", wrongVerifyResponse.Code, wrongVerifyResponse.Body.String())
	}

	code := computeTestTOTP(t, startBody.Enrollment.Secret, time.Now().UTC())
	verifyRequest := httptest.NewRequest(http.MethodPost, "/api/v1/auth/totp/verify", bytes.NewBufferString(fmt.Sprintf(`{"code":%q}`, code)))
	addDashboardAuth(verifyRequest, cookies[0], loginBody.CSRFToken)
	verifyResponse := httptest.NewRecorder()
	router.ServeHTTP(verifyResponse, verifyRequest)
	if verifyResponse.Code != http.StatusOK {
		t.Fatalf("verify status = %d body = %s", verifyResponse.Code, verifyResponse.Body.String())
	}
	var verifyBody struct {
		User struct {
			TwoFactorEnabled bool `json:"two_factor_enabled"`
			TwoFactorPending bool `json:"two_factor_pending"`
		} `json:"user"`
	}
	if err := json.NewDecoder(verifyResponse.Body).Decode(&verifyBody); err != nil {
		t.Fatalf("Decode verify returned error: %v", err)
	}
	if !verifyBody.User.TwoFactorEnabled || verifyBody.User.TwoFactorPending {
		t.Fatalf("verify body = %#v, want enabled and not pending", verifyBody)
	}

	missingCSRFRequest := httptest.NewRequest(http.MethodPatch, "/api/v1/access/users/"+createBody.User.ID, bytes.NewBufferString(`{
		"display_name":"Blocked",
		"access_level":"admin",
		"status":"active",
		"two_factor_required":true
	}`))
	missingCSRFRequest.AddCookie(cookies[0])
	missingCSRFResponse := httptest.NewRecorder()
	router.ServeHTTP(missingCSRFResponse, missingCSRFRequest)
	if missingCSRFResponse.Code != http.StatusForbidden {
		t.Fatalf("missing csrf status = %d body = %s", missingCSRFResponse.Code, missingCSRFResponse.Body.String())
	}

	patchRequest := httptest.NewRequest(http.MethodPatch, "/api/v1/access/users/"+createBody.User.ID, bytes.NewBufferString(`{
		"display_name":"Security Admin",
		"access_level":"admin",
		"status":"active",
		"two_factor_required":false
	}`))
	addDashboardAuth(patchRequest, cookies[0], loginBody.CSRFToken)
	patchResponse := httptest.NewRecorder()
	router.ServeHTTP(patchResponse, patchRequest)
	if patchResponse.Code != http.StatusOK {
		t.Fatalf("patch status = %d body = %s", patchResponse.Code, patchResponse.Body.String())
	}
	var patchBody struct {
		User struct {
			TwoFactorRequired bool `json:"two_factor_required"`
		} `json:"user"`
	}
	if err := json.NewDecoder(patchResponse.Body).Decode(&patchBody); err != nil {
		t.Fatalf("Decode patch returned error: %v", err)
	}
	if patchBody.User.TwoFactorRequired {
		t.Fatalf("patch ignored disabling 2FA requirement")
	}

	listRequest := httptest.NewRequest(http.MethodGet, "/api/v1/access/users", nil)
	listRequest.AddCookie(cookies[0])
	listResponse := httptest.NewRecorder()
	router.ServeHTTP(listResponse, listRequest)
	if listResponse.Code != http.StatusOK {
		t.Fatalf("list status = %d body = %s", listResponse.Code, listResponse.Body.String())
	}
	var listBody struct {
		Count int `json:"count"`
		Users []struct {
			ID     string `json:"id"`
			Secret string `json:"totp_secret_ciphertext"`
		} `json:"users"`
	}
	if err := json.NewDecoder(listResponse.Body).Decode(&listBody); err != nil {
		t.Fatalf("Decode list returned error: %v", err)
	}
	if listBody.Count != 1 || listBody.Users[0].ID != createBody.User.ID || listBody.Users[0].Secret != "" {
		t.Fatalf("list body = %#v, want one user and no secret material", listBody)
	}

	disableRequest := httptest.NewRequest(http.MethodDelete, "/api/v1/access/users/"+createBody.User.ID+"/totp", nil)
	addDashboardAuth(disableRequest, cookies[0], loginBody.CSRFToken)
	disableResponse := httptest.NewRecorder()
	router.ServeHTTP(disableResponse, disableRequest)
	if disableResponse.Code != http.StatusOK {
		t.Fatalf("disable status = %d body = %s", disableResponse.Code, disableResponse.Body.String())
	}
	var disableBody struct {
		User struct {
			TwoFactorEnabled bool `json:"two_factor_enabled"`
		} `json:"user"`
	}
	if err := json.NewDecoder(disableResponse.Body).Decode(&disableBody); err != nil {
		t.Fatalf("Decode disable returned error: %v", err)
	}
	if disableBody.User.TwoFactorEnabled {
		t.Fatalf("disable did not turn 2FA off")
	}

	postDisableListRequest := httptest.NewRequest(http.MethodGet, "/api/v1/access/users", nil)
	postDisableListRequest.AddCookie(cookies[0])
	postDisableListResponse := httptest.NewRecorder()
	router.ServeHTTP(postDisableListResponse, postDisableListRequest)
	if postDisableListResponse.Code != http.StatusOK {
		t.Fatalf("post-disable list status = %d body = %s", postDisableListResponse.Code, postDisableListResponse.Body.String())
	}
}

func TestHubUserDashboardReadyDoesNotRequireOptional2FA(t *testing.T) {
	if !hubUserDashboardReady(domain.HubUser{TwoFactorRequired: false}) {
		t.Fatalf("optional 2FA user should be dashboard-ready without enrollment")
	}
	if hubUserDashboardReady(domain.HubUser{TwoFactorRequired: true}) {
		t.Fatalf("required 2FA user should not be dashboard-ready before enrollment")
	}
	if !hubUserDashboardReady(domain.HubUser{
		TwoFactorRequired:    true,
		TwoFactorEnabled:     true,
		TOTPSecretCiphertext: "v1:nonce:ciphertext",
	}) {
		t.Fatalf("required 2FA user should be dashboard-ready after enrollment")
	}
}

func addDashboardAuth(request *http.Request, cookie *http.Cookie, csrfToken string) {
	request.AddCookie(cookie)
	request.Header.Set(headerDashboardProto, dashboardProtocol)
	request.Header.Set(headerDashboardCSRF, csrfToken)
}

func computeTestTOTP(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		t.Fatalf("decode secret: %v", err)
	}
	counter := uint64(at.UTC().Unix() / 30)
	var counterBytes [8]byte
	binary.BigEndian.PutUint64(counterBytes[:], counter)
	mac := hmac.New(sha1.New, raw)
	mac.Write(counterBytes[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := (uint32(sum[offset])&0x7f)<<24 |
		(uint32(sum[offset+1])&0xff)<<16 |
		(uint32(sum[offset+2])&0xff)<<8 |
		(uint32(sum[offset+3]) & 0xff)
	return fmt.Sprintf("%06d", value%1000000)
}

type httpTestHubUserRepository struct {
	sessions map[string]domain.HubUserSession
	users    map[domain.ID]domain.HubUser
	next     int
	nextSess int
}

func newHTTPTestHubUserRepository() *httpTestHubUserRepository {
	return &httpTestHubUserRepository{
		sessions: map[string]domain.HubUserSession{},
		users:    map[domain.ID]domain.HubUser{},
	}
}

func (r *httpTestHubUserRepository) SaveHubUser(ctx context.Context, user domain.HubUser) (domain.HubUser, error) {
	now := time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC)
	for id, existing := range r.users {
		if existing.Email == user.Email {
			user.ID = id
			user.CreatedAt = existing.CreatedAt
			user.UpdatedAt = now
			if user.PasswordHash == "" {
				user.PasswordHash = existing.PasswordHash
				user.PasswordSetAt = existing.PasswordSetAt
			}
			user.TwoFactorEnabled = existing.TwoFactorEnabled
			user.TOTPSecretCiphertext = existing.TOTPSecretCiphertext
			user.TOTPEnrolledAt = existing.TOTPEnrolledAt
			user.PendingTOTPSecretCiphertext = existing.PendingTOTPSecretCiphertext
			user.PendingTOTPStartedAt = existing.PendingTOTPStartedAt
			r.users[id] = user
			return user, nil
		}
	}
	r.next++
	user.ID = domain.ID(fmt.Sprintf("user-%d", r.next))
	user.CreatedAt = now
	user.UpdatedAt = now
	r.users[user.ID] = user
	return user, nil
}

func (r *httpTestHubUserRepository) ListHubUsers(ctx context.Context) ([]domain.HubUser, error) {
	users := make([]domain.HubUser, 0, len(r.users))
	for _, user := range r.users {
		users = append(users, user)
	}
	return users, nil
}

func (r *httpTestHubUserRepository) CountHubUsers(ctx context.Context) (int, error) {
	return len(r.users), nil
}

func (r *httpTestHubUserRepository) FindHubUserByEmail(ctx context.Context, email string) (domain.HubUser, bool, error) {
	for _, user := range r.users {
		if user.Email == email {
			return user, true, nil
		}
	}
	return domain.HubUser{}, false, nil
}

func (r *httpTestHubUserRepository) FindHubUserByID(ctx context.Context, userID domain.ID) (domain.HubUser, bool, error) {
	user, ok := r.users[userID]
	return user, ok, nil
}

func (r *httpTestHubUserRepository) UpdateHubUser(ctx context.Context, userID domain.ID, update domain.HubUserUpdate) (domain.HubUser, error) {
	user, ok := r.users[userID]
	if !ok {
		return domain.HubUser{}, fmt.Errorf("user %q was not found", userID)
	}
	user.DisplayName = update.DisplayName
	user.AccessLevel = update.AccessLevel
	user.Status = update.Status
	user.TwoFactorRequired = update.TwoFactorRequired
	user.UpdatedAt = time.Date(2026, 5, 14, 12, 5, 0, 0, time.UTC)
	r.users[userID] = user
	return user, nil
}

func (r *httpTestHubUserRepository) StartHubUserTOTP(ctx context.Context, userID domain.ID, start domain.HubUserTOTPStart) (domain.HubUser, error) {
	user, ok := r.users[userID]
	if !ok {
		return domain.HubUser{}, fmt.Errorf("user %q was not found", userID)
	}
	user.PendingTOTPSecretCiphertext = start.PendingSecretCiphertext
	startedAt := start.StartedAt
	user.PendingTOTPStartedAt = &startedAt
	user.UpdatedAt = startedAt
	r.users[userID] = user
	return user, nil
}

func (r *httpTestHubUserRepository) ActivateHubUserTOTP(ctx context.Context, userID domain.ID, activation domain.HubUserTOTPActivation) (domain.HubUser, error) {
	user, ok := r.users[userID]
	if !ok {
		return domain.HubUser{}, fmt.Errorf("user %q was not found", userID)
	}
	user.TOTPSecretCiphertext = activation.ActiveSecretCiphertext
	user.TwoFactorEnabled = true
	user.TwoFactorRequired = true
	enrolledAt := activation.EnrolledAt
	user.TOTPEnrolledAt = &enrolledAt
	user.PendingTOTPSecretCiphertext = ""
	user.PendingTOTPStartedAt = nil
	user.UpdatedAt = enrolledAt
	r.users[userID] = user
	return user, nil
}

func (r *httpTestHubUserRepository) DisableHubUserTOTP(ctx context.Context, userID domain.ID) (domain.HubUser, error) {
	user, ok := r.users[userID]
	if !ok {
		return domain.HubUser{}, fmt.Errorf("user %q was not found", userID)
	}
	user.TOTPSecretCiphertext = ""
	user.TwoFactorEnabled = false
	user.TOTPEnrolledAt = nil
	user.PendingTOTPSecretCiphertext = ""
	user.PendingTOTPStartedAt = nil
	user.UpdatedAt = time.Date(2026, 5, 14, 12, 9, 0, 0, time.UTC)
	r.users[userID] = user
	return user, nil
}

func (r *httpTestHubUserRepository) SaveHubUserSession(ctx context.Context, session domain.HubUserSession) (domain.HubUserSession, error) {
	r.nextSess++
	session.ID = domain.ID(fmt.Sprintf("session-%d", r.nextSess))
	r.sessions[session.TokenHash] = session
	user := r.users[session.UserID]
	loginAt := session.CreatedAt
	user.LastLoginAt = &loginAt
	r.users[session.UserID] = user
	return session, nil
}

func (r *httpTestHubUserRepository) FindHubUserBySessionTokenHash(ctx context.Context, tokenHash string, now time.Time) (domain.HubUser, domain.HubUserSession, bool, error) {
	session, ok := r.sessions[tokenHash]
	if !ok || session.RevokedAt != nil || !session.ExpiresAt.After(now) {
		return domain.HubUser{}, domain.HubUserSession{}, false, nil
	}
	user, ok := r.users[session.UserID]
	if !ok {
		return domain.HubUser{}, domain.HubUserSession{}, false, nil
	}
	return user, session, true, nil
}

func (r *httpTestHubUserRepository) TouchHubUserSession(ctx context.Context, tokenHash string, seenAt time.Time) error {
	session, ok := r.sessions[tokenHash]
	if ok {
		session.LastSeenAt = seenAt
		r.sessions[tokenHash] = session
	}
	return nil
}

func (r *httpTestHubUserRepository) RevokeHubUserSession(ctx context.Context, tokenHash string, revokedAt time.Time) error {
	session, ok := r.sessions[tokenHash]
	if ok {
		session.RevokedAt = &revokedAt
		r.sessions[tokenHash] = session
	}
	return nil
}
