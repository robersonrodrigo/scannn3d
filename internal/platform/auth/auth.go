package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"scannn3d/internal/platform/storage"

	"golang.org/x/crypto/bcrypt"
)

type Claims struct {
	Sub  string       `json:"sub"`
	Role storage.Role `json:"role"`
	Typ  string       `json:"typ,omitempty"`
	Exp  int64        `json:"exp"`
}

const (
	TokenTypeAccess  = "access"
	TokenTypeRefresh = "refresh"
)

func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func ValidatePasswordPolicy(password string) error {
	if len(password) < 8 {
		return fmt.Errorf("password must have at least 8 characters")
	}
	hasLetter := false
	hasDigit := false
	for _, r := range password {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			hasLetter = true
		}
		if r >= '0' && r <= '9' {
			hasDigit = true
		}
	}
	if !hasLetter || !hasDigit {
		return fmt.Errorf("password must contain at least one letter and one number")
	}
	return nil
}

func VerifyPassword(hash, password string) bool {
	// Bcrypt is the current format.
	if strings.HasPrefix(hash, "$2a$") || strings.HasPrefix(hash, "$2b$") || strings.HasPrefix(hash, "$2y$") {
		return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
	}
	// Legacy compatibility: salt:sha256(salt||password).
	return verifyLegacySHA256(hash, password)
}

func verifyLegacySHA256(hash, password string) bool {
	parts := strings.Split(hash, ":")
	if len(parts) != 2 {
		return false
	}
	salt, err := hex.DecodeString(parts[0])
	if err != nil {
		return false
	}
	expected, err := hex.DecodeString(parts[1])
	if err != nil {
		return false
	}
	h := sha256.Sum256(append(salt, []byte(password)...))
	return hmac.Equal(h[:], expected)
}

func IssueAccessToken(secret []byte, userID string, role storage.Role, ttl time.Duration) (string, error) {
	return IssueToken(secret, userID, role, TokenTypeAccess, ttl)
}

func IssueRefreshToken(secret []byte, userID string, role storage.Role, ttl time.Duration) (string, error) {
	return IssueToken(secret, userID, role, TokenTypeRefresh, ttl)
}

func IssueToken(secret []byte, userID string, role storage.Role, tokenType string, ttl time.Duration) (string, error) {
	if len(secret) == 0 {
		return "", errors.New("missing token secret")
	}
	if tokenType != TokenTypeAccess && tokenType != TokenTypeRefresh {
		return "", errors.New("invalid token type")
	}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	claims := Claims{Sub: userID, Role: role, Typ: tokenType, Exp: time.Now().Add(ttl).Unix()}
	payloadBytes, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	signed := header + "." + payload
	sig := sign(secret, signed)
	return signed + "." + sig, nil
}

func ParseToken(secret []byte, token string) (Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, errors.New("invalid token format")
	}
	signed := parts[0] + "." + parts[1]
	expected := sign(secret, signed)
	if !hmac.Equal([]byte(expected), []byte(parts[2])) {
		return Claims{}, errors.New("invalid token signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Claims{}, err
	}
	var c Claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return Claims{}, err
	}
	if c.Exp < time.Now().Unix() {
		return Claims{}, errors.New("token expired")
	}
	return c, nil
}

func ParseTokenOfType(secret []byte, token, expectedType string) (Claims, error) {
	claims, err := ParseToken(secret, token)
	if err != nil {
		return Claims{}, err
	}
	if claims.Typ == "" {
		if expectedType == TokenTypeAccess {
			return claims, nil
		}
		return Claims{}, errors.New("unexpected token type")
	}
	if claims.Typ != expectedType {
		return Claims{}, errors.New("unexpected token type")
	}
	return claims, nil
}

func sign(secret []byte, data string) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(data))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func BearerToken(header string) (string, error) {
	parts := strings.SplitN(strings.TrimSpace(header), " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", fmt.Errorf("invalid authorization header")
	}
	return strings.TrimSpace(parts[1]), nil
}
