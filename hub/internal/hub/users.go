package hub

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/rcooler/aegrail/hub/internal/domain"
	"github.com/rcooler/aegrail/hub/internal/ports"
	qrcode "github.com/skip2/go-qrcode"
)

type CreateHubUserInput struct {
	Email             string
	DisplayName       string
	AccessLevel       string
	Password          string
	Status            string
	TwoFactorRequired bool
}

type CreateBootstrapHubUserResult struct {
	User    domain.HubUser
	Created bool
}

type UpdateHubUserInput struct {
	UserID            string
	DisplayName       string
	AccessLevel       string
	Status            string
	TwoFactorRequired bool
}

type StartHubUserTOTPInput struct {
	UserID string
	Issuer string
}

type StartHubUserTOTPResult struct {
	User          domain.HubUser
	Secret        string
	OTPAuthURL    string
	QRCodeDataURL string
}

type VerifyHubUserTOTPInput struct {
	UserID string
	Code   string
}

type VerifyHubUserTOTPResult struct {
	User domain.HubUser
}

type DisableHubUserTOTPInput struct {
	UserID string
}

type DisableHubUserTOTPResult struct {
	User domain.HubUser
}

type DeleteHubUserInput struct {
	UserID string
}

var ErrHubTOTPNoPending = errors.New("no pending 2FA enrolment for this user")

var ErrHubTOTPInvalidCode = errors.New("verification code is incorrect")

var ErrHubTOTPChanged = ports.ErrHubTOTPChanged

func (h *Hub) CreateHubUser(ctx context.Context, input CreateHubUserInput) (domain.HubUser, error) {
	if h.users == nil {
		return domain.HubUser{}, errors.New("hub user repository is not configured")
	}
	email, err := normalizeHubUserEmail(input.Email)
	if err != nil {
		return domain.HubUser{}, err
	}
	accessLevel, err := normalizeHubUserAccessLevel(input.AccessLevel)
	if err != nil {
		return domain.HubUser{}, err
	}
	status, err := normalizeHubUserStatus(input.Status)
	if err != nil {
		return domain.HubUser{}, err
	}
	passwordHash, passwordSetAt, err := hashHubPassword(input.Password, time.Now().UTC())
	if err != nil {
		return domain.HubUser{}, err
	}
	if status == "active" && passwordHash == "" {
		return domain.HubUser{}, errors.New("password is required for active users")
	}
	if _, exists, err := h.users.FindHubUserByEmail(ctx, email); err != nil {
		return domain.HubUser{}, err
	} else if exists {
		return domain.HubUser{}, ErrHubUserExists
	}
	user, err := h.users.SaveHubUser(ctx, domain.HubUser{
		Email:             email,
		DisplayName:       strings.TrimSpace(input.DisplayName),
		AccessLevel:       accessLevel,
		Status:            status,
		PasswordHash:      passwordHash,
		PasswordSetAt:     passwordSetAt,
		TwoFactorRequired: input.TwoFactorRequired,
	})
	if err != nil {
		return domain.HubUser{}, err
	}
	h.markHubUsersExist()
	return user, nil
}

func (h *Hub) CreateBootstrapHubUser(ctx context.Context, input CreateHubUserInput) (CreateBootstrapHubUserResult, error) {
	if h.users == nil {
		return CreateBootstrapHubUserResult{}, errors.New("hub user repository is not configured")
	}
	email, err := normalizeHubUserEmail(input.Email)
	if err != nil {
		return CreateBootstrapHubUserResult{}, err
	}
	passwordHash, passwordSetAt, err := hashHubPassword(input.Password, time.Now().UTC())
	if err != nil {
		return CreateBootstrapHubUserResult{}, err
	}
	if passwordHash == "" {
		return CreateBootstrapHubUserResult{}, errors.New("password is required for active users")
	}
	user := domain.HubUser{
		Email:             email,
		DisplayName:       strings.TrimSpace(input.DisplayName),
		AccessLevel:       "owner",
		Status:            "active",
		PasswordHash:      passwordHash,
		PasswordSetAt:     passwordSetAt,
		TwoFactorRequired: true,
	}
	if bootstrapRepo, ok := h.users.(ports.BootstrapHubUserRepository); ok {
		createdUser, created, err := bootstrapRepo.CreateBootstrapHubUser(ctx, user)
		if err != nil {
			return CreateBootstrapHubUserResult{}, err
		}
		if created {
			h.markHubUsersExist()
		}
		return CreateBootstrapHubUserResult{User: createdUser, Created: created}, nil
	}
	count, err := h.users.CountHubUsers(ctx)
	if err != nil {
		return CreateBootstrapHubUserResult{}, err
	}
	if count > 0 {
		h.markHubUsersExist()
		return CreateBootstrapHubUserResult{}, nil
	}
	createdUser, err := h.users.SaveHubUser(ctx, user)
	if err != nil {
		return CreateBootstrapHubUserResult{}, err
	}
	h.markHubUsersExist()
	return CreateBootstrapHubUserResult{User: createdUser, Created: true}, nil
}

func (h *Hub) ListHubUsers(ctx context.Context) ([]domain.HubUser, error) {
	if h.users == nil {
		return nil, errors.New("hub user repository is not configured")
	}
	return h.users.ListHubUsers(ctx)
}

func (h *Hub) UpdateHubUser(ctx context.Context, input UpdateHubUserInput) (domain.HubUser, error) {
	if h.users == nil {
		return domain.HubUser{}, errors.New("hub user repository is not configured")
	}
	userID := domain.ID(strings.TrimSpace(input.UserID))
	if userID == "" {
		return domain.HubUser{}, errors.New("user id is required")
	}
	accessLevel, err := normalizeHubUserAccessLevel(input.AccessLevel)
	if err != nil {
		return domain.HubUser{}, err
	}
	status, err := normalizeHubUserStatus(input.Status)
	if err != nil {
		return domain.HubUser{}, err
	}
	if err := h.ensureHubUserUpdateKeepsOwner(ctx, userID, accessLevel, status); err != nil {
		return domain.HubUser{}, err
	}
	return h.users.UpdateHubUser(ctx, userID, domain.HubUserUpdate{
		DisplayName:       strings.TrimSpace(input.DisplayName),
		AccessLevel:       accessLevel,
		Status:            status,
		TwoFactorRequired: input.TwoFactorRequired,
	})
}

func (h *Hub) DeleteHubUser(ctx context.Context, input DeleteHubUserInput) error {
	if h.users == nil {
		return errors.New("hub user repository is not configured")
	}
	userID := domain.ID(strings.TrimSpace(input.UserID))
	if userID == "" {
		return errors.New("user id is required")
	}
	if err := h.ensureHubUserDeleteKeepsOwner(ctx, userID); err != nil {
		return err
	}
	deleteRepo, ok := h.users.(ports.DeleteHubUserRepository)
	if !ok {
		return errors.New("hub user repository does not support user deletion")
	}
	remaining, err := deleteRepo.DeleteHubUser(ctx, userID)
	if err != nil {
		return err
	}
	if remaining == 0 {
		h.markHubUsersUnknown()
	}
	return nil
}

func (h *Hub) ensureHubUserUpdateKeepsOwner(ctx context.Context, userID domain.ID, nextAccessLevel string, nextStatus string) error {
	user, ok, err := h.users.FindHubUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if !ok {
		return ErrHubNotFound
	}
	if !hubUserIsActiveOwner(user) || hubUserUpdateIsActiveOwner(nextAccessLevel, nextStatus) {
		return nil
	}
	return h.ensureAnotherActiveOwner(ctx, userID)
}

func (h *Hub) ensureHubUserDeleteKeepsOwner(ctx context.Context, userID domain.ID) error {
	user, ok, err := h.users.FindHubUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if !ok {
		return ErrHubNotFound
	}
	if !hubUserIsActiveOwner(user) {
		return nil
	}
	return h.ensureAnotherActiveOwner(ctx, userID)
}

func (h *Hub) ensureAnotherActiveOwner(ctx context.Context, excludedUserID domain.ID) error {
	users, err := h.users.ListHubUsers(ctx)
	if err != nil {
		return err
	}
	for _, user := range users {
		if user.ID != excludedUserID && hubUserIsActiveOwner(user) {
			return nil
		}
	}
	return ErrHubLastOwner
}

func hubUserIsActiveOwner(user domain.HubUser) bool {
	return strings.EqualFold(strings.TrimSpace(user.AccessLevel), "owner") &&
		strings.EqualFold(strings.TrimSpace(user.Status), "active")
}

func hubUserUpdateIsActiveOwner(accessLevel string, status string) bool {
	return strings.EqualFold(strings.TrimSpace(accessLevel), "owner") &&
		strings.EqualFold(strings.TrimSpace(status), "active")
}

func (h *Hub) StartHubUserTOTP(ctx context.Context, input StartHubUserTOTPInput) (StartHubUserTOTPResult, error) {
	if h.users == nil {
		return StartHubUserTOTPResult{}, errors.New("hub user repository is not configured")
	}
	userID := domain.ID(strings.TrimSpace(input.UserID))
	if userID == "" {
		return StartHubUserTOTPResult{}, errors.New("user id is required")
	}
	secret, err := newTOTPSecret()
	if err != nil {
		return StartHubUserTOTPResult{}, err
	}
	ciphertext, err := encryptHubUserSecret(h.userSecretKey, secret)
	if err != nil {
		return StartHubUserTOTPResult{}, err
	}
	now := time.Now().UTC()
	user, err := h.users.StartHubUserTOTP(ctx, userID, domain.HubUserTOTPStart{
		PendingSecretCiphertext: ciphertext,
		StartedAt:               now,
	})
	if err != nil {
		return StartHubUserTOTPResult{}, err
	}
	issuer := strings.TrimSpace(input.Issuer)
	if issuer == "" {
		issuer = "Aegrail"
	}
	otpauthURL := totpAuthURL(issuer, user.Email, secret)
	qrCodeDataURL, err := totpQRCodeDataURL(otpauthURL)
	if err != nil {
		return StartHubUserTOTPResult{}, err
	}
	return StartHubUserTOTPResult{
		User:          user,
		Secret:        secret,
		OTPAuthURL:    otpauthURL,
		QRCodeDataURL: qrCodeDataURL,
	}, nil
}

func (h *Hub) VerifyHubUserTOTP(ctx context.Context, input VerifyHubUserTOTPInput) (VerifyHubUserTOTPResult, error) {
	if h.users == nil {
		return VerifyHubUserTOTPResult{}, errors.New("hub user repository is not configured")
	}
	userID := domain.ID(strings.TrimSpace(input.UserID))
	if userID == "" {
		return VerifyHubUserTOTPResult{}, errors.New("user id is required")
	}
	code := strings.TrimSpace(strings.ReplaceAll(input.Code, " ", ""))
	if code == "" {
		return VerifyHubUserTOTPResult{}, ErrHubTOTPInvalidCode
	}
	user, ok, err := h.users.FindHubUserByID(ctx, userID)
	if err != nil {
		return VerifyHubUserTOTPResult{}, err
	}
	if !ok {
		return VerifyHubUserTOTPResult{}, errors.New("user not found")
	}
	if strings.TrimSpace(user.PendingTOTPSecretCiphertext) == "" {
		return VerifyHubUserTOTPResult{}, ErrHubTOTPNoPending
	}
	secret, err := decryptHubUserSecret(h.userSecretKey, user.PendingTOTPSecretCiphertext)
	if err != nil {
		return VerifyHubUserTOTPResult{}, err
	}
	if !h.verifyAndConsumeTOTPCode(userID, secret, code, time.Now().UTC()) {
		return VerifyHubUserTOTPResult{}, ErrHubTOTPInvalidCode
	}
	activated, err := h.users.ActivateHubUserTOTP(ctx, userID, domain.HubUserTOTPActivation{
		ActiveSecretCiphertext:          user.PendingTOTPSecretCiphertext,
		ExpectedPendingSecretCiphertext: user.PendingTOTPSecretCiphertext,
		EnrolledAt:                      time.Now().UTC(),
	})
	if err != nil {
		return VerifyHubUserTOTPResult{}, err
	}
	return VerifyHubUserTOTPResult{User: activated}, nil
}

func (h *Hub) DisableHubUserTOTP(ctx context.Context, input DisableHubUserTOTPInput) (DisableHubUserTOTPResult, error) {
	if h.users == nil {
		return DisableHubUserTOTPResult{}, errors.New("hub user repository is not configured")
	}
	userID := domain.ID(strings.TrimSpace(input.UserID))
	if userID == "" {
		return DisableHubUserTOTPResult{}, errors.New("user id is required")
	}
	user, err := h.users.DisableHubUserTOTP(ctx, userID)
	if err != nil {
		return DisableHubUserTOTPResult{}, err
	}
	return DisableHubUserTOTPResult{User: user}, nil
}

func normalizeHubUserEmail(value string) (string, error) {
	email := strings.ToLower(strings.TrimSpace(value))
	if email == "" {
		return "", errors.New("email is required")
	}
	if !strings.Contains(email, "@") || strings.ContainsAny(email, " \t\r\n") {
		return "", fmt.Errorf("email %q is invalid", value)
	}
	return email, nil
}

func normalizeHubUserAccessLevel(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "viewer", "read_only", "readonly", "read-only":
		return "viewer", nil
	case "operator", "triage", "analyst":
		return "operator", nil
	case "admin", "administrator":
		return "admin", nil
	case "owner":
		return "owner", nil
	default:
		return "", fmt.Errorf("access level %q is not supported", value)
	}
}

func normalizeHubUserStatus(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "active", "enabled":
		return "active", nil
	case "invited", "pending":
		return "invited", nil
	case "disabled", "inactive":
		return "disabled", nil
	default:
		return "", fmt.Errorf("user status %q is not supported", value)
	}
}

func newTOTPSecret() (string, error) {
	var raw [20]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	encoder := base32.StdEncoding.WithPadding(base32.NoPadding)
	return encoder.EncodeToString(raw[:]), nil
}

func totpAuthURL(issuer string, email string, secret string) string {
	values := url.Values{}
	values.Set("secret", secret)
	values.Set("issuer", issuer)
	values.Set("algorithm", "SHA1")
	values.Set("digits", "6")
	values.Set("period", "30")
	label := url.PathEscape(issuer + ":" + email)
	return "otpauth://totp/" + label + "?" + values.Encode()
}

func totpQRCodeDataURL(otpauthURL string) (string, error) {
	png, err := qrcode.Encode(otpauthURL, qrcode.Medium, 256)
	if err != nil {
		return "", err
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(png), nil
}

func encryptHubUserSecret(secretKey string, plaintext string) (string, error) {
	secretKey = strings.TrimSpace(secretKey)
	if secretKey == "" {
		return "", errors.New("AEGRAIL_HUB_USER_SECRET is required before enrolling 2FA")
	}
	key, err := deriveHubUserSecretKey(secretKey)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nil, nonce, []byte(plaintext), nil)
	return "v2:" + base64.RawURLEncoding.EncodeToString(nonce) + ":" + base64.RawURLEncoding.EncodeToString(ciphertext), nil
}

func deriveHubUserSecretKey(secretKey string) ([]byte, error) {
	return hkdf.Key(sha256.New, []byte(secretKey), nil, "aegrail.hub.user-security.v2", 32)
}
