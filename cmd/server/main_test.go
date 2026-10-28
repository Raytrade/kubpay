package main

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func TestPaystackSignatureVerification(t *testing.T) {
	app := &App{cfg: Config{PaystackSecretKey: "test-secret"}}
	body := []byte(`{"event":"transfer.success","data":{"reference":"KUB-TEST"}}`)

	mac := hmac.New(sha512.New, []byte(app.cfg.PaystackSecretKey))
	_, _ = mac.Write(body)
	valid := hex.EncodeToString(mac.Sum(nil))

	if !app.verifyPaystackSignature(body, valid) {
		t.Fatal("expected valid signature to be accepted")
	}
	if !app.verifyPaystackSignature(body, upperHex(valid)) {
		t.Fatal("expected uppercase hex signature to be accepted")
	}
	if app.verifyPaystackSignature(body, valid+"00") {
		t.Fatal("expected tampered signature to be rejected")
	}
	if app.verifyPaystackSignature(body, "") {
		t.Fatal("expected missing signature to be rejected")
	}
	if (&App{}).verifyPaystackSignature(body, valid) {
		t.Fatal("expected missing secret to reject signature")
	}
}

func upperHex(value string) string {
	const lower = "abcdef"
	const upper = "ABCDEF"
	out := []byte(value)
	for i, b := range out {
		for j := range lower {
			if b == lower[j] {
				out[i] = upper[j]
				break
			}
		}
	}
	return string(out)
}

func TestPayoutFailureActionHandlesReversalAfterSuccess(t *testing.T) {
	tests := []struct {
		name   string
		status string
		event  string
		want   string
	}{
		{name: "successful payout reversed", status: "SUCCESS", event: "transfer.reversed", want: "CREDIT_REVERSAL"},
		{name: "successful payout failure replay", status: "SUCCESS", event: "transfer.failed", want: "NOOP"},
		{name: "duplicate reversal", status: "REVERSED", event: "transfer.reversed", want: "NOOP"},
		{name: "duplicate failure", status: "FAILED", event: "transfer.failed", want: "NOOP"},
		{name: "pending payout failure", status: "PROCESSING", event: "transfer.failed", want: "RELEASE_RESERVED"},
		{name: "unknown payout reversal", status: "UNKNOWN", event: "transfer.reversed", want: "RELEASE_RESERVED"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := payoutFailureAction(tt.status, tt.event); got != tt.want {
				t.Fatalf("payoutFailureAction(%q, %q) = %q, want %q", tt.status, tt.event, got, tt.want)
			}
		})
	}
}

func TestWebhookEventIDIsDeterministicAndPayloadSensitive(t *testing.T) {
	body := []byte(`{"event":"transfer.success"}`)
	first := webhookEventID("transfer.success", "KUB-1", body)
	if first == "" {
		t.Fatal("event id should not be empty")
	}
	if got := webhookEventID("transfer.success", "KUB-1", body); got != first {
		t.Fatalf("same event produced different IDs: %q != %q", got, first)
	}
	if got := webhookEventID("transfer.failed", "KUB-1", body); got == first {
		t.Fatal("different event should produce a different ID")
	}
	if got := webhookEventID("transfer.success", "KUB-1", []byte("changed")); got == first {
		t.Fatal("different payload should produce a different ID")
	}
}

func TestAuthMiddlewareRejectsMissingAndInvalidTokens(t *testing.T) {
	gin.SetMode(gin.TestMode)
	app := &App{cfg: Config{JWTSecret: "unit-test-secret-with-enough-entropy"}}

	tests := []struct {
		name  string
		token string
		want  int
	}{
		{name: "missing", token: "", want: http.StatusUnauthorized},
		{name: "invalid", token: "not-a-jwt", want: http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, "/protected", nil)
			if tt.token != "" {
				request.Header.Set("Authorization", "Bearer "+tt.token)
			}
			ctx, _ := gin.CreateTestContext(recorder)
			ctx.Request = request
			app.authMiddleware()(ctx)
			if recorder.Code != tt.want {
				t.Fatalf("status = %d, want %d", recorder.Code, tt.want)
			}
		})
	}
}

func TestAuthMiddlewareAcceptsValidToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	app := &App{cfg: Config{JWTSecret: "unit-test-secret-with-enough-entropy"}}
	user := User{ID: uuid.NewString(), Email: "test@example.com", Role: "USER"}
	token, err := app.createToken(user)
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/protected", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = request
	app.authMiddleware()(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	if got, ok := ctx.Get("user_id"); !ok || got != user.ID {
		t.Fatalf("user_id context = %v, present = %v; want %s", got, ok, user.ID)
	}
	if got, ok := ctx.Get("role"); !ok || got != user.Role {
		t.Fatalf("role context = %v, present = %v; want %s", got, ok, user.Role)
	}
}

func TestAuthMiddlewareRejectsExpiredToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	app := &App{cfg: Config{JWTSecret: "unit-test-secret-with-enough-entropy"}}
	claims := Claims{
		UserID: uuid.NewString(),
		Role:   "FOUNDER",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   uuid.NewString(),
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-48 * time.Hour)),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-24 * time.Hour)),
		},
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(app.cfg.JWTSecret))
	if err != nil {
		t.Fatalf("sign expired token: %v", err)
	}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/protected", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = request
	app.authMiddleware()(ctx)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusUnauthorized)
	}
}
