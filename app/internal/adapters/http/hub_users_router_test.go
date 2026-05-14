package httpadapter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rcooler/aegrail/internal/domain"
	hubapp "github.com/rcooler/aegrail/internal/hub"
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
	cookies := loginResponse.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatalf("login did not set a session cookie")
	}

	patchRequest := httptest.NewRequest(http.MethodPatch, "/api/v1/access/users/"+createBody.User.ID, bytes.NewBufferString(`{
		"display_name":"Security Admin",
		"access_level":"admin",
		"status":"active",
		"two_factor_required":true
	}`))
	patchRequest.AddCookie(cookies[0])
	patchResponse := httptest.NewRecorder()
	router.ServeHTTP(patchResponse, patchRequest)
	if patchResponse.Code != http.StatusOK {
		t.Fatalf("patch status = %d body = %s", patchResponse.Code, patchResponse.Body.String())
	}

	totpRequest := httptest.NewRequest(http.MethodPost, "/api/v1/access/users/"+createBody.User.ID+"/totp", bytes.NewBufferString(`{"issuer":"Aegrail Local"}`))
	totpRequest.AddCookie(cookies[0])
	totpResponse := httptest.NewRecorder()
	router.ServeHTTP(totpResponse, totpRequest)
	if totpResponse.Code != http.StatusCreated {
		t.Fatalf("totp status = %d body = %s", totpResponse.Code, totpResponse.Body.String())
	}
	var totpBody struct {
		User struct {
			TwoFactorEnabled bool `json:"two_factor_enabled"`
		} `json:"user"`
		Enrollment struct {
			OTPAuthURL    string `json:"otpauth_url"`
			QRCodeDataURL string `json:"qr_code_data_url"`
			Secret        string `json:"secret"`
		} `json:"enrollment"`
	}
	if err := json.NewDecoder(totpResponse.Body).Decode(&totpBody); err != nil {
		t.Fatalf("Decode TOTP returned error: %v", err)
	}
	if !totpBody.User.TwoFactorEnabled || totpBody.Enrollment.Secret == "" || !stringsContains(totpBody.Enrollment.OTPAuthURL, "otpauth://totp/") || !stringsContains(totpBody.Enrollment.QRCodeDataURL, "data:image/png;base64,") {
		t.Fatalf("totp body = %#v, want enabled user and otpauth enrollment", totpBody)
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

func (r *httpTestHubUserRepository) UpdateHubUserTOTP(ctx context.Context, userID domain.ID, update domain.HubUserTOTPUpdate) (domain.HubUser, error) {
	user, ok := r.users[userID]
	if !ok {
		return domain.HubUser{}, fmt.Errorf("user %q was not found", userID)
	}
	user.TOTPSecretCiphertext = update.SecretCiphertext
	user.TwoFactorEnabled = true
	user.TwoFactorRequired = true
	user.TOTPEnrolledAt = &update.EnrolledAt
	user.UpdatedAt = update.EnrolledAt
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

func stringsContains(value string, needle string) bool {
	return len(needle) == 0 || (len(value) >= len(needle) && bytes.Contains([]byte(value), []byte(needle)))
}
