package hub

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/rcooler/aegrail/internal/domain"
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

type UpdateHubUserInput struct {
	UserID            string
	DisplayName       string
	AccessLevel       string
	Status            string
	TwoFactorRequired bool
}

type GenerateHubUserTOTPInput struct {
	UserID string
	Issuer string
}

type GenerateHubUserTOTPResult struct {
	User          domain.HubUser
	Secret        string
	OTPAuthURL    string
	QRCodeDataURL string
}

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
	return h.users.SaveHubUser(ctx, domain.HubUser{
		Email:             email,
		DisplayName:       strings.TrimSpace(input.DisplayName),
		AccessLevel:       accessLevel,
		Status:            status,
		PasswordHash:      passwordHash,
		PasswordSetAt:     passwordSetAt,
		TwoFactorRequired: input.TwoFactorRequired,
	})
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
	return h.users.UpdateHubUser(ctx, userID, domain.HubUserUpdate{
		DisplayName:       strings.TrimSpace(input.DisplayName),
		AccessLevel:       accessLevel,
		Status:            status,
		TwoFactorRequired: input.TwoFactorRequired,
	})
}

func (h *Hub) GenerateHubUserTOTP(ctx context.Context, input GenerateHubUserTOTPInput) (GenerateHubUserTOTPResult, error) {
	if h.users == nil {
		return GenerateHubUserTOTPResult{}, errors.New("hub user repository is not configured")
	}
	userID := domain.ID(strings.TrimSpace(input.UserID))
	if userID == "" {
		return GenerateHubUserTOTPResult{}, errors.New("user id is required")
	}
	secret, err := newTOTPSecret()
	if err != nil {
		return GenerateHubUserTOTPResult{}, err
	}
	ciphertext, err := encryptHubUserSecret(h.userSecretKey, secret)
	if err != nil {
		return GenerateHubUserTOTPResult{}, err
	}
	now := time.Now().UTC()
	user, err := h.users.UpdateHubUserTOTP(ctx, userID, domain.HubUserTOTPUpdate{
		SecretCiphertext: ciphertext,
		EnrolledAt:       now,
	})
	if err != nil {
		return GenerateHubUserTOTPResult{}, err
	}
	issuer := strings.TrimSpace(input.Issuer)
	if issuer == "" {
		issuer = "Aegrail"
	}
	otpauthURL := totpAuthURL(issuer, user.Email, secret)
	qrCodeDataURL, err := totpQRCodeDataURL(otpauthURL)
	if err != nil {
		return GenerateHubUserTOTPResult{}, err
	}
	return GenerateHubUserTOTPResult{
		User:          user,
		Secret:        secret,
		OTPAuthURL:    otpauthURL,
		QRCodeDataURL: qrCodeDataURL,
	}, nil
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
		return "", errors.New("AEGRAIL_HUB_USER_SECRET or AEGRAIL_HUB_INGEST_SECRET is required before enrolling 2FA")
	}
	key := sha256.Sum256([]byte(secretKey))
	block, err := aes.NewCipher(key[:])
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
	return "v1:" + base64.RawURLEncoding.EncodeToString(nonce) + ":" + base64.RawURLEncoding.EncodeToString(ciphertext), nil
}
