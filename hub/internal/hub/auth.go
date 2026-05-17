package hub

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"strconv"
	"strings"
	"time"

	"github.com/rcooler/aegrail/hub/internal/domain"
)

const (
	hubPasswordHashAlgorithm = "pbkdf2-sha256"
	hubPasswordHashVersion   = "v1"
	hubPasswordIterations    = 210000
	hubPasswordKeyLength     = 32
	hubPasswordSaltLength    = 16
	HubSessionTTL            = 12 * time.Hour
)

var (
	ErrHubAuthRequired        = errors.New("authentication required")
	ErrHubAuthForbidden       = errors.New("insufficient access")
	ErrHubAuthBootstrapNeeded = errors.New("hub user bootstrap required")
	ErrHubInvalidCredentials  = errors.New("invalid email or password")
	ErrHubMFARequired         = errors.New("mfa required")
)

type totpReplayKey struct {
	UserID  domain.ID
	Counter int64
}

type LoginHubUserInput struct {
	Email    string
	Password string
	TOTPCode string
	Now      time.Time
}

type LoginHubUserResult struct {
	User      domain.HubUser
	Session   domain.HubUserSession
	Token     string
	ExpiresAt time.Time
}

func (h *Hub) HubUsersConfigured() bool {
	return h != nil && h.users != nil
}

func (h *Hub) CountHubUsers(ctx context.Context) (int, error) {
	if h.users == nil {
		return 0, nil
	}
	return h.users.CountHubUsers(ctx)
}

func (h *Hub) HubUsersExist(ctx context.Context) (bool, error) {
	if h == nil || h.users == nil {
		return false, nil
	}
	h.usersExistMu.RLock()
	if h.usersExist {
		h.usersExistMu.RUnlock()
		return true, nil
	}
	h.usersExistMu.RUnlock()
	count, err := h.users.CountHubUsers(ctx)
	if err != nil {
		return false, err
	}
	if count > 0 {
		h.markHubUsersExist()
		return true, nil
	}
	return false, nil
}

func (h *Hub) markHubUsersExist() {
	if h == nil {
		return
	}
	h.usersExistMu.Lock()
	h.usersExist = true
	h.usersExistMu.Unlock()
}

func (h *Hub) LoginHubUser(ctx context.Context, input LoginHubUserInput) (LoginHubUserResult, error) {
	if h.users == nil {
		return LoginHubUserResult{}, errors.New("hub user repository is not configured")
	}
	email, err := normalizeHubUserEmail(input.Email)
	if err != nil {
		return LoginHubUserResult{}, ErrHubInvalidCredentials
	}
	user, ok, err := h.users.FindHubUserByEmail(ctx, email)
	if err != nil {
		return LoginHubUserResult{}, err
	}
	if !ok || user.Status != "active" || !verifyHubPassword(input.Password, user.PasswordHash) {
		return LoginHubUserResult{}, ErrHubInvalidCredentials
	}
	if user.TwoFactorEnabled && strings.TrimSpace(user.TOTPSecretCiphertext) != "" {
		valid, err := h.verifyHubUserTOTP(user, input.TOTPCode, input.Now)
		if err != nil {
			return LoginHubUserResult{}, err
		}
		if !valid {
			return LoginHubUserResult{}, ErrHubMFARequired
		}
	}

	now := input.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	token, tokenHash, err := newHubSessionToken()
	if err != nil {
		return LoginHubUserResult{}, err
	}
	session, err := h.users.SaveHubUserSession(ctx, domain.HubUserSession{
		UserID:     user.ID,
		TokenHash:  tokenHash,
		ExpiresAt:  now.Add(HubSessionTTL),
		CreatedAt:  now,
		LastSeenAt: now,
	})
	if err != nil {
		return LoginHubUserResult{}, err
	}
	user.LastLoginAt = &now
	return LoginHubUserResult{
		User:      user,
		Session:   session,
		Token:     token,
		ExpiresAt: session.ExpiresAt,
	}, nil
}

func (h *Hub) HubUserForSession(ctx context.Context, token string, now time.Time) (domain.HubUser, bool, error) {
	if h.users == nil {
		return domain.HubUser{}, false, nil
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return domain.HubUser{}, false, nil
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tokenHash := hashHubSessionToken(token)
	user, _, ok, err := h.users.FindHubUserBySessionTokenHash(ctx, tokenHash, now.UTC())
	if err != nil || !ok {
		return domain.HubUser{}, false, err
	}
	if user.Status != "active" {
		return domain.HubUser{}, false, nil
	}
	if err := h.users.TouchHubUserSession(ctx, tokenHash, now.UTC()); err != nil {
		return domain.HubUser{}, false, err
	}
	return user, true, nil
}

func (h *Hub) LogoutHubUser(ctx context.Context, token string, now time.Time) error {
	if h.users == nil {
		return nil
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return nil
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	return h.users.RevokeHubUserSession(ctx, hashHubSessionToken(token), now.UTC())
}

func HubUserHasAccess(user domain.HubUser, minimum string) bool {
	return hubAccessRank(user.AccessLevel) >= hubAccessRank(minimum)
}

func hubAccessRank(level string) int {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "owner":
		return 4
	case "admin":
		return 3
	case "operator":
		return 2
	case "viewer", "":
		return 1
	default:
		return 0
	}
}

func hashHubPassword(password string, now time.Time) (string, *time.Time, error) {
	password = strings.TrimSpace(password)
	if password == "" {
		return "", nil, nil
	}
	if len(password) < 12 {
		return "", nil, errors.New("password must be at least 12 characters")
	}
	var salt [hubPasswordSaltLength]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return "", nil, err
	}
	key, err := pbkdf2.Key[hash.Hash](sha256.New, password, salt[:], hubPasswordIterations, hubPasswordKeyLength)
	if err != nil {
		return "", nil, err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	setAt := now.UTC()
	encoded := strings.Join([]string{
		hubPasswordHashAlgorithm,
		hubPasswordHashVersion,
		strconv.Itoa(hubPasswordIterations),
		base64.RawStdEncoding.EncodeToString(salt[:]),
		base64.RawStdEncoding.EncodeToString(key),
	}, "$")
	return encoded, &setAt, nil
}

func verifyHubPassword(password string, stored string) bool {
	password = strings.TrimSpace(password)
	stored = strings.TrimSpace(stored)
	if password == "" || stored == "" {
		return false
	}
	parts := strings.Split(stored, "$")
	if len(parts) != 5 || parts[0] != hubPasswordHashAlgorithm || parts[1] != hubPasswordHashVersion {
		return false
	}
	iterations, err := strconv.Atoi(parts[2])
	if err != nil || iterations <= 0 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(expected) == 0 {
		return false
	}
	actual, err := pbkdf2.Key[hash.Hash](sha256.New, password, salt, iterations, len(expected))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(actual, expected) == 1
}

func newHubSessionToken() (string, string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw[:])
	return token, hashHubSessionToken(token), nil
}

func hashHubSessionToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (h *Hub) verifyHubUserTOTP(user domain.HubUser, code string, at time.Time) (bool, error) {
	code = strings.TrimSpace(strings.ReplaceAll(code, " ", ""))
	if code == "" {
		return false, nil
	}
	secret, err := decryptHubUserSecret(h.userSecretKey, user.TOTPSecretCiphertext)
	if err != nil {
		return false, err
	}
	return h.verifyAndConsumeTOTPCode(user.ID, secret, code, at), nil
}

func verifyTOTPCode(secret string, code string, at time.Time) bool {
	_, ok := verifyTOTPCodeCounter(secret, code, at)
	return ok
}

func (h *Hub) verifyAndConsumeTOTPCode(userID domain.ID, secret string, code string, at time.Time) bool {
	counter, ok := verifyTOTPCodeCounter(secret, code, at)
	if !ok {
		return false
	}
	return h.consumeTOTPCode(userID, counter, at)
}

func verifyTOTPCodeCounter(secret string, code string, at time.Time) (int64, bool) {
	if at.IsZero() {
		at = time.Now().UTC()
	}
	secret = strings.ToUpper(strings.TrimSpace(secret))
	secretBytes, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		return 0, false
	}
	counter := at.UTC().Unix() / 30
	for offset := int64(-1); offset <= 1; offset++ {
		if generateTOTPCode(secretBytes, uint64(counter+offset)) == code {
			return counter + offset, true
		}
	}
	return 0, false
}

func (h *Hub) consumeTOTPCode(userID domain.ID, counter int64, at time.Time) bool {
	if h == nil {
		return true
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}
	now := at.UTC()
	h.totpReplayMu.Lock()
	defer h.totpReplayMu.Unlock()
	if h.totpReplay == nil {
		h.totpReplay = map[totpReplayKey]time.Time{}
	}
	for key, expiresAt := range h.totpReplay {
		if !expiresAt.After(now) {
			delete(h.totpReplay, key)
		}
	}
	key := totpReplayKey{UserID: userID, Counter: counter}
	if expiresAt, exists := h.totpReplay[key]; exists && expiresAt.After(now) {
		return false
	}
	h.totpReplay[key] = now.Add(90 * time.Second)
	return true
}

func generateTOTPCode(secret []byte, counter uint64) string {
	var counterBytes [8]byte
	binary.BigEndian.PutUint64(counterBytes[:], counter)
	mac := hmac.New(sha1.New, secret)
	mac.Write(counterBytes[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := (uint32(sum[offset])&0x7f)<<24 |
		(uint32(sum[offset+1])&0xff)<<16 |
		(uint32(sum[offset+2])&0xff)<<8 |
		(uint32(sum[offset+3]) & 0xff)
	return fmt.Sprintf("%06d", value%1000000)
}

func decryptHubUserSecret(secretKey string, ciphertextValue string) (string, error) {
	secretKey = strings.TrimSpace(secretKey)
	if secretKey == "" {
		return "", errors.New("AEGRAIL_HUB_USER_SECRET is required before verifying 2FA")
	}
	parts := strings.Split(strings.TrimSpace(ciphertextValue), ":")
	if len(parts) != 3 || parts[0] != "v1" {
		return "", errors.New("stored 2FA secret is invalid")
	}
	nonce, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", errors.New("stored 2FA nonce is invalid")
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", errors.New("stored 2FA ciphertext is invalid")
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
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", errors.New("stored 2FA secret could not be decrypted")
	}
	return string(plaintext), nil
}
