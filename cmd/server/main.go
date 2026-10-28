package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha512"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"github.com/shopspring/decimal"
	"golang.org/x/crypto/bcrypt"

	_ "github.com/jackc/pgx/v5/stdlib"
)

type Config struct {
	Port                 string
	DatabaseURL          string
	JWTSecret            string
	PaystackSecretKey    string
	RequireApproval      bool
	MaxTransferKobo      int64
	DailyTransferKobo    int64
}

type App struct {
	db  *sql.DB
	cfg Config
}

type Claims struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

type User struct {
	ID           string `json:"id"`
	Email        string `json:"email"`
	Role         string `json:"role"`
	PasswordHash string `json:"-"`
}

type RegisterRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
}

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type PayoutRequest struct {
	AccountNumber string `json:"account_number" binding:"required"`
	BankCode      string `json:"bank_code" binding:"required"`
	AccountName   string `json:"account_name"`
	AmountKobo    int64  `json:"amount_kobo" binding:"required,min=1"`
	Reason        string `json:"reason"`
}

type PaystackRecipientRequest struct {
	Type          string `json:"type"`
	Name          string `json:"name"`
	AccountNumber string `json:"account_number"`
	BankCode      string `json:"bank_code"`
	Currency      string `json:"currency"`
}

type PaystackRecipientResponse struct {
	Status  bool   `json:"status"`
	Message string `json:"message"`
	Data    struct {
		RecipientCode string `json:"recipient_code"`
		Name          string `json:"name"`
		Details       struct {
			AccountNumber string `json:"account_number"`
			AccountName   string `json:"account_name"`
			BankCode      string `json:"bank_code"`
			BankName      string `json:"bank_name"`
		} `json:"details"`
	} `json:"data"`
}

type PaystackTransferRequest struct {
	Source    string `json:"source"`
	Amount    int64  `json:"amount"`
	Recipient string `json:"recipient"`
	Reference string `json:"reference"`
	Reason    string `json:"reason"`
	Currency  string `json:"currency"`
}

type PaystackTransferResponse struct {
	Status  bool   `json:"status"`
	Message string `json:"message"`
	Data    struct {
		Reference    string `json:"reference"`
		Status       string `json:"status"`
		TransferCode string `json:"transfer_code"`
	} `json:"data"`
}

func main() {
	_ = godotenv.Load()

	cfg := Config{
		Port:              getenv("PORT", "8080"),
		DatabaseURL:       os.Getenv("DATABASE_URL"),
		JWTSecret:         os.Getenv("JWT_SECRET"),
		PaystackSecretKey: os.Getenv("PAYSTACK_SECRET_KEY"),
		RequireApproval:   getenvBool("PAYOUT_REQUIRE_APPROVAL", true),
		MaxTransferKobo:   getenvInt64("MAX_TRANSFER_KOBO", 5000000),
		DailyTransferKobo: getenvInt64("DAILY_TRANSFER_KOBO", 5000000000),
	}

	if cfg.DatabaseURL == "" {
		log.Fatal("DATABASE_URL is required")
	}

	if cfg.JWTSecret == "" {
		log.Fatal("JWT_SECRET is required")
	}

	db, err := sql.Open("pgx", cfg.DatabaseURL)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		log.Fatal("database connection failed: ", err)
	}

	app := &App{
		db:  db,
		cfg: cfg,
	}

	router := gin.Default()

	router.GET("/health", app.health)
	router.GET("/ready", app.ready)

	api := router.Group("/api/v1")

	api.POST("/register", app.register)
	api.POST("/login", app.login)

	protected := api.Group("/")
	protected.Use(app.authMiddleware())

	protected.GET("/me", app.me)
	protected.GET("/balance", app.balance)
	protected.GET("/transactions", app.transactions)
	protected.GET("/banks", app.banks)
	protected.POST("/resolve-account", app.resolveAccount)
	protected.POST("/payouts", app.createPayout)
	protected.GET("/payouts", app.listPayouts)

	admin := protected.Group("/admin")
	admin.Use(app.adminMiddleware())
	admin.POST("/payouts/:id/approve", app.approvePayout)
	admin.POST("/payouts/:id/reject", app.rejectPayout)

	router.POST("/webhooks/paystack", app.paystackWebhook)

	log.Printf("KubPay server listening on :%s", cfg.Port)

	if err := router.Run(":" + cfg.Port); err != nil {
		log.Fatal(err)
	}
}

func getenv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func getenvBool(key string, fallback bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}

	result, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}

	return result
}

func getenvInt64(key string, fallback int64) int64 {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}

	result, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return fallback
	}

	return result
}

func (a *App) health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":  "ok",
		"service": "kubpay",
	})
}

func (a *App) ready(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 3*time.Second)
	defer cancel()

	if err := a.db.PingContext(ctx); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"status": "not_ready",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status": "ready",
	})
}

func (a *App) register(c *gin.Context) {
	var req RegisterRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))

	hash, err := bcrypt.GenerateFromPassword(
		[]byte(req.Password),
		bcrypt.DefaultCost,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "password hashing failed"})
		return
	}

	id := uuid.NewString()

	_, err = a.db.ExecContext(
		c.Request.Context(),
		`INSERT INTO users
			(id, email, password_hash, role)
		 VALUES ($1, $2, $3, 'USER')`,
		id,
		email,
		string(hash),
	)

	if err != nil {
		c.JSON(http.StatusConflict, gin.H{
			"error": "account could not be created",
		})
		return
	}

	_, err = a.db.ExecContext(
		c.Request.Context(),
		`INSERT INTO wallets
			(id, user_id, currency, available_kobo, reserved_kobo)
		 VALUES ($1, $2, 'NGN', 0, 0)`,
		uuid.NewString(),
		id,
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "wallet creation failed",
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"id":    id,
		"email": email,
	})
}

func (a *App) login(c *gin.Context) {
	var req LoginRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user User

	err := a.db.QueryRowContext(
		c.Request.Context(),
		`SELECT id, email, password_hash, role
		 FROM users
		 WHERE email = $1`,
		strings.ToLower(strings.TrimSpace(req.Email)),
	).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.Role,
	)

	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "login failed"})
		return
	}

	if err := bcrypt.CompareHashAndPassword(
		[]byte(user.PasswordHash),
		[]byte(req.Password),
	); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	token, err := a.createToken(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "token creation failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token": token,
		"user": gin.H{
			"id":    user.ID,
			"email": user.Email,
			"role":  user.Role,
		},
	})
}

func (a *App) createToken(user User) (string, error) {
	now := time.Now()

	claims := Claims{
		UserID: user.ID,
		Role:   user.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   user.ID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(24 * time.Hour)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString([]byte(a.cfg.JWTSecret))
}

func (a *App) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")

		if !strings.HasPrefix(header, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "missing bearer token",
			})
			return
		}

		tokenString := strings.TrimSpace(
			strings.TrimPrefix(header, "Bearer "),
		)

		token, err := jwt.ParseWithClaims(
			tokenString,
			&Claims{},
			func(token *jwt.Token) (interface{}, error) {
				if token.Method != jwt.SigningMethodHS256 {
					return nil, errors.New("unexpected signing method")
				}
				return []byte(a.cfg.JWTSecret), nil
			},
		)

		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid or expired token",
			})
			return
		}

		claims, ok := token.Claims.(*Claims)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid claims",
			})
			return
		}

		c.Set("user_id", claims.UserID)
		c.Set("role", claims.Role)

		c.Next()
	}
}

func (a *App) adminMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		role, exists := c.Get("role")

		if !exists {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "admin access required",
			})
			return
		}

		if role != "ADMIN" && role != "FOUNDER" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "admin access required",
			})
			return
		}

		c.Next()
	}
}

func (a *App) currentUserID(c *gin.Context) string {
	value, exists := c.Get("user_id")
	if !exists {
		return ""
	}

	userID, ok := value.(string)
	if !ok {
		return ""
	}

	return userID
}

func (a *App) me(c *gin.Context) {
	userID := a.currentUserID(c)

	var user User

	err := a.db.QueryRowContext(
		c.Request.Context(),
		`SELECT id, email, role
		 FROM users
		 WHERE id = $1`,
		userID,
	).Scan(
		&user.ID,
		&user.Email,
		&user.Role,
	)

	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":    user.ID,
		"email": user.Email,
		"role":  user.Role,
	})
}

func (a *App) balance(c *gin.Context) {
	userID := a.currentUserID(c)

	var available int64
	var reserved int64

	err := a.db.QueryRowContext(
		c.Request.Context(),
		`SELECT available_kobo, reserved_kobo
		 FROM wallets
		 WHERE user_id = $1
		   AND currency = 'NGN'`,
		userID,
	).Scan(&available, &reserved)

	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "wallet not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"currency":        "NGN",
		"available_kobo":  available,
		"reserved_kobo":   reserved,
		"available_naira": decimal.NewFromInt(available).Div(decimal.NewFromInt(100)),
	})
}

func (a *App) banks(c *gin.Context) {
	if a.cfg.PaystackSecretKey == "" {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "Paystack is not configured",
		})
		return
	}

	body, err := a.paystackRequest(
		c.Request.Context(),
		http.MethodGet,
		"https://api.paystack.co/bank?currency=NGN&country=nigeria&perPage=100",
		nil,
	)

	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{
			"error": "bank list unavailable",
		})
		return
	}

	c.Data(http.StatusOK, "application/json", body)
}

func (a *App) resolveAccount(c *gin.Context) {
	var req struct {
		AccountNumber string `json:"account_number" binding:"required"`
		BankCode      string `json:"bank_code" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	url := fmt.Sprintf(
		"https://api.paystack.co/bank/resolve?account_number=%s&bank_code=%s",
		req.AccountNumber,
		req.BankCode,
	)

	body, err := a.paystackRequest(
		c.Request.Context(),
		http.MethodGet,
		url,
		nil,
	)

	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{
			"error": "account resolution failed",
		})
		return
	}

	c.Data(http.StatusOK, "application/json", body)
}

func (a *App) createPayout(c *gin.Context) {
	userID := a.currentUserID(c)

	var req PayoutRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.AmountKobo <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "amount must be positive"})
		return
	}

	if req.AmountKobo > a.cfg.MaxTransferKobo {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "transfer exceeds single-transfer limit",
		})
		return
	}

	idempotencyKey := strings.TrimSpace(
		c.GetHeader("Idempotency-Key"),
	)

	if idempotencyKey == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Idempotency-Key is required",
		})
		return
	}

	reference := "KUB-" + strings.ToUpper(
		strings.ReplaceAll(uuid.NewString(), "-", ""),
	)[:20]

	status := "PENDING_APPROVAL"

	if !a.cfg.RequireApproval {
		status = "PROCESSING"
	}

	tx, err := a.db.BeginTx(
		c.Request.Context(),
		&sql.TxOptions{},
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "transaction failed"})
		return
	}

	defer tx.Rollback()

	var existingBody []byte
	var existingCode int

	err = tx.QueryRowContext(
		c.Request.Context(),
		`SELECT response_code, response_body
		 FROM idempotency_keys
		 WHERE user_id = $1 AND key = $2`,
		userID,
		idempotencyKey,
	).Scan(&existingCode, &existingBody)

	if err == nil {
		c.Data(existingCode, "application/json", existingBody)
		return
	}

	if !errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "idempotency lookup failed",
		})
		return
	}

	var available int64

	err = tx.QueryRowContext(
		c.Request.Context(),
		`SELECT available_kobo
		 FROM wallets
		 WHERE user_id = $1
		   AND currency = 'NGN'
		 FOR UPDATE`,
		userID,
	).Scan(&available)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "wallet not found",
		})
		return
	}

	if available < req.AmountKobo {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "insufficient available balance",
		})
		return
	}

	var dailyTotal int64

	err = tx.QueryRowContext(
		c.Request.Context(),
		`SELECT COALESCE(SUM(amount_kobo), 0)
		 FROM payouts
		 WHERE user_id = $1
		   AND created_at >= CURRENT_DATE
		   AND status NOT IN ('FAILED', 'REJECTED', 'REVERSED')`,
		userID,
	).Scan(&dailyTotal)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "daily limit check failed",
		})
		return
	}

	if dailyTotal+req.AmountKobo > a.cfg.DailyTransferKobo {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "daily transfer limit exceeded",
		})
		return
	}

	payoutID := uuid.NewString()

	_, err = tx.ExecContext(
		c.Request.Context(),
		`UPDATE wallets
		 SET available_kobo = available_kobo - $1,
		     reserved_kobo = reserved_kobo + $1,
		     updated_at = NOW()
		 WHERE user_id = $2
		   AND currency = 'NGN'`,
		req.AmountKobo,
		userID,
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "fund reservation failed",
		})
		return
	}

	_, err = tx.ExecContext(
		c.Request.Context(),
		`INSERT INTO payouts
			(id, user_id, reference, account_number, bank_code,
			 account_name, amount_kobo, status, approval_status,
			 created_at, updated_at)
		 VALUES
			($1,$2,$3,$4,$5,$6,$7,$8,$9,NOW(),NOW())`,
		payoutID,
		userID,
		reference,
		req.AccountNumber,
		req.BankCode,
		req.AccountName,
		req.AmountKobo,
		status,
		func() string {
			if a.cfg.RequireApproval {
				return "PENDING"
			}
			return "APPROVED"
		}(),
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "payout creation failed",
		})
		return
	}

	response := gin.H{
		"id":         payoutID,
		"reference":  reference,
		"status":     status,
		"amount_kobo": req.AmountKobo,
	}

	responseBody, _ := json.Marshal(response)

	_, err = tx.ExecContext(
		c.Request.Context(),
		`INSERT INTO idempotency_keys
			(user_id, key, response_code, response_body)
		 VALUES ($1,$2,$3,$4)`,
		userID,
		idempotencyKey,
		http.StatusCreated,
		responseBody,
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "idempotency record failed",
		})
		return
	}

	_, _ = tx.ExecContext(
		c.Request.Context(),
		`INSERT INTO audit_logs
			(id, actor_user_id, action, entity_type, entity_id, details)
		 VALUES ($1,$2,'PAYOUT_CREATED','PAYOUT',$3,$4)`,
		uuid.NewString(),
		userID,
		payoutID,
		json.RawMessage(`{}`),
	)

	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "payout commit failed",
		})
		return
	}

	if !a.cfg.RequireApproval {
		go func() {
			if err := a.executePayout(
				context.Background(),
				payoutID,
			); err != nil {
				log.Printf("payout execution error: %v", err)
			}
		}()
	}

	c.JSON(http.StatusCreated, response)
}

func (a *App) executePayout(ctx context.Context, payoutID string) error {
	if a.cfg.PaystackSecretKey == "" {
		return errors.New("Paystack is not configured")
	}

	var payout struct {
		ID            string
		UserID        string
		Reference     string
		AccountNumber string
		BankCode      string
		AccountName   string
		AmountKobo    int64
		Status        string
	}

	err := a.db.QueryRowContext(
		ctx,
		`SELECT id,user_id,reference,account_number,bank_code,
		        account_name,amount_kobo,status
		 FROM payouts
		 WHERE id = $1`,
		payoutID,
	).Scan(
		&payout.ID,
		&payout.UserID,
		&payout.Reference,
		&payout.AccountNumber,
		&payout.BankCode,
		&payout.AccountName,
		&payout.AmountKobo,
		&payout.Status,
	)

	if err != nil {
		return err
	}

	if payout.Status != "PROCESSING" {
		return nil
	}

	recipientPayload := PaystackRecipientRequest{
		Type:          "nuban",
		Name:          payout.AccountName,
		AccountNumber: payout.AccountNumber,
		BankCode:      payout.BankCode,
		Currency:      "NGN",
	}

	recipientBody, _ := json.Marshal(recipientPayload)

	recipientResponse, err := a.paystackRequest(
		ctx,
		http.MethodPost,
		"https://api.paystack.co/transferrecipient",
		recipientBody,
	)

	if err != nil {
		_ = a.markPayoutUnknown(ctx, payoutID, err.Error())
		return err
	}

	var recipient PaystackRecipientResponse

	if err := json.Unmarshal(recipientResponse, &recipient); err != nil {
		_ = a.markPayoutUnknown(ctx, payoutID, "invalid Paystack recipient response")
		return err
	}

	if !recipient.Status || recipient.Data.RecipientCode == "" {
		message := recipient.Message
		if message == "" {
			message = "Paystack recipient creation failed"
		}

		_ = a.failPayout(ctx, payoutID, message)
		return errors.New(message)
	}

	transferPayload := PaystackTransferRequest{
		Source:    "balance",
		Amount:    payout.AmountKobo,
		Recipient: recipient.Data.RecipientCode,
		Reference: payout.Reference,
		Reason:    "KubPay payout",
		Currency:  "NGN",
	}

	transferBody, _ := json.Marshal(transferPayload)

	transferResponse, err := a.paystackRequest(
		ctx,
		http.MethodPost,
		"https://api.paystack.co/transfer",
		transferBody,
	)

	if err != nil {
		_ = a.markPayoutUnknown(ctx, payoutID, err.Error())
		return err
	}

	var transfer PaystackTransferResponse

	if err := json.Unmarshal(transferResponse, &transfer); err != nil {
		_ = a.markPayoutUnknown(ctx, payoutID, "invalid Paystack transfer response")
		return err
	}

	if !transfer.Status {
		message := transfer.Message
		if message == "" {
			message = "Paystack transfer failed"
		}

		_ = a.failPayout(ctx, payoutID, message)
		return errors.New(message)
	}

	_, err = a.db.ExecContext(
		ctx,
		`UPDATE payouts
		 SET recipient_code = $1,
		     provider_status = $2,
		     provider_response = $3,
		     status = 'PROCESSING',
		     updated_at = NOW()
		 WHERE id = $4`,
		recipient.Data.RecipientCode,
		transfer.Data.Status,
		transferResponse,
		payoutID,
	)

	return err
}

func (a *App) paystackRequest(
	ctx context.Context,
	method string,
	url string,
	body []byte,
) ([]byte, error) {
	req, err := http.NewRequestWithContext(
		ctx,
		method,
		url,
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, err
	}

	req.Header.Set(
		"Authorization",
		"Bearer "+a.cfg.PaystackSecretKey,
	)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return responseBody, fmt.Errorf(
			"Paystack returned HTTP %d",
			resp.StatusCode,
		)
	}

	return responseBody, nil
}

func (a *App) listPayouts(c *gin.Context) {
	userID := a.currentUserID(c)

	rows, err := a.db.QueryContext(
		c.Request.Context(),
		`SELECT id,reference,account_number,bank_code,
		        account_name,amount_kobo,status,approval_status,
		        provider_status,created_at,updated_at
		 FROM payouts
		 WHERE user_id = $1
		 ORDER BY created_at DESC
		 LIMIT 100`,
		userID,
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "could not load payouts",
		})
		return
	}

	defer rows.Close()

	type payoutView struct {
		ID            string    `json:"id"`
		Reference     string    `json:"reference"`
		AccountNumber string    `json:"account_number"`
		BankCode      string    `json:"bank_code"`
		AccountName   string    `json:"account_name"`
		AmountKobo    int64     `json:"amount_kobo"`
		Status        string    `json:"status"`
		Approval      string    `json:"approval_status"`
		Provider      string    `json:"provider_status"`
		CreatedAt     time.Time `json:"created_at"`
		UpdatedAt     time.Time `json:"updated_at"`
	}

	result := make([]payoutView, 0)

	for rows.Next() {
		var item payoutView

		if err := rows.Scan(
			&item.ID,
			&item.Reference,
			&item.AccountNumber,
			&item.BankCode,
			&item.AccountName,
			&item.AmountKobo,
			&item.Status,
			&item.Approval,
			&item.Provider,
			&item.CreatedAt,
			&item.UpdatedAt,
		); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "could not read payout",
			})
			return
		}

		result = append(result, item)
	}

	c.JSON(http.StatusOK, gin.H{
		"payouts": result,
	})
}

func (a *App) transactions(c *gin.Context) {
	userID := a.currentUserID(c)

	rows, err := a.db.QueryContext(
		c.Request.Context(),
		`SELECT id,kind,amount_kobo,reference,created_at
		 FROM ledger_entries
		 WHERE user_id = $1
		 ORDER BY created_at DESC
		 LIMIT 100`,
		userID,
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "could not load transactions",
		})
		return
	}

	defer rows.Close()

	type transactionView struct {
		ID         string    `json:"id"`
		Kind       string    `json:"kind"`
		AmountKobo int64     `json:"amount_kobo"`
		Reference  string    `json:"reference"`
		CreatedAt  time.Time `json:"created_at"`
	}

	result := make([]transactionView, 0)

	for rows.Next() {
		var item transactionView

		if err := rows.Scan(
			&item.ID,
			&item.Kind,
			&item.AmountKobo,
			&item.Reference,
			&item.CreatedAt,
		); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "could not read transaction",
			})
			return
		}

		result = append(result, item)
	}

	c.JSON(http.StatusOK, gin.H{
		"transactions": result,
	})
}

func (a *App) approvePayout(c *gin.Context) {
	payoutID := c.Param("id")

	result, err := a.db.ExecContext(
		c.Request.Context(),
		`UPDATE payouts
		 SET approval_status = 'APPROVED',
		     status = 'PROCESSING',
		     updated_at = NOW()
		 WHERE id = $1
		   AND approval_status = 'PENDING'`,
		payoutID,
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "approval failed",
		})
		return
	}

	count, _ := result.RowsAffected()

	if count == 0 {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "payout not found or already processed",
		})
		return
	}

	go func() {
		if err := a.executePayout(
			context.Background(),
			payoutID,
		); err != nil {
			log.Printf("approved payout execution error: %v", err)
		}
	}()

	c.JSON(http.StatusOK, gin.H{
		"status": "PROCESSING",
		"id":     payoutID,
	})
}

func (a *App) rejectPayout(c *gin.Context) {
	payoutID := c.Param("id")

	tx, err := a.db.BeginTx(
		c.Request.Context(),
		&sql.TxOptions{},
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "transaction failed",
		})
		return
	}

	defer tx.Rollback()

	var userID string
	var amount int64

	err = tx.QueryRowContext(
		c.Request.Context(),
		`SELECT user_id,amount_kobo
		 FROM payouts
		 WHERE id = $1
		   AND approval_status = 'PENDING'
		 FOR UPDATE`,
		payoutID,
	).Scan(&userID, &amount)

	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "pending payout not found",
		})
		return
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "payout lookup failed",
		})
		return
	}

	_, err = tx.ExecContext(
		c.Request.Context(),
		`UPDATE wallets
		 SET available_kobo = available_kobo + $1,
		     reserved_kobo = reserved_kobo - $1,
		     updated_at = NOW()
		 WHERE user_id = $2
		   AND currency = 'NGN'`,
		amount,
		userID,
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "fund release failed",
		})
		return
	}

	_, err = tx.ExecContext(
		c.Request.Context(),
		`UPDATE payouts
		 SET approval_status = 'REJECTED',
		     status = 'REJECTED',
		     updated_at = NOW()
		 WHERE id = $1`,
		payoutID,
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "rejection failed",
		})
		return
	}

	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "rejection commit failed",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":     payoutID,
		"status": "REJECTED",
	})
}

func (a *App) paystackWebhook(c *gin.Context) {
	rawBody, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}

	signature := c.GetHeader("x-paystack-signature")

	if !a.verifyPaystackSignature(rawBody, signature) {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "invalid signature",
		})
		return
	}

	var event struct {
		Event string `json:"event"`
		Data  struct {
			Reference string `json:"reference"`
			Status    string `json:"status"`
			Amount    int64  `json:"amount"`
		} `json:"data"`
	}

	if err := json.Unmarshal(rawBody, &event); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid webhook JSON",
		})
		return
	}

	eventID := webhookEventID(event.Event, event.Data.Reference, rawBody)

	_, err = a.db.ExecContext(
		c.Request.Context(),
		`INSERT INTO webhook_events
			(event_id,event_type,payload)
		 VALUES ($1,$2,$3)
		 ON CONFLICT (event_id) DO NOTHING`,
		eventID,
		event.Event,
		rawBody,
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "webhook record failed",
		})
		return
	}

	switch event.Event {
	case "transfer.success":
		if err := a.settleSuccessfulPayout(
			c.Request.Context(),
			event.Data.Reference,
			rawBody,
		); err != nil {
			log.Printf("settlement error: %v", err)
		}

	case "transfer.failed", "transfer.reversed":
		if err := a.failPayoutByReference(
			c.Request.Context(),
			event.Data.Reference,
			event.Event,
		); err != nil {
			log.Printf("payout failure processing error: %v", err)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"received": true,
	})
}

func (a *App) verifyPaystackSignature(
	body []byte,
	signature string,
) bool {
	if signature == "" || a.cfg.PaystackSecretKey == "" {
		return false
	}

	mac := hmac.New(
		sha512.New,
		[]byte(a.cfg.PaystackSecretKey),
	)

	_, _ = mac.Write(body)

	expected := hex.EncodeToString(mac.Sum(nil))

	return hmac.Equal(
		[]byte(strings.ToLower(signature)),
		[]byte(strings.ToLower(expected)),
	)
}

func webhookEventID(event, reference string, body []byte) string {
	hash := sha512.Sum512(
		[]byte(event + "|" + reference + "|" + string(body)),
	)

	return hex.EncodeToString(hash[:])
}

func (a *App) settleSuccessfulPayout(
	ctx context.Context,
	reference string,
	providerResponse []byte,
) error {
	tx, err := a.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return err
	}

	defer tx.Rollback()

	var userID string
	var amount int64
	var status string

	err = tx.QueryRowContext(
		ctx,
		`SELECT user_id,amount_kobo,status
		 FROM payouts
		 WHERE reference = $1
		 FOR UPDATE`,
		reference,
	).Scan(
		&userID,
		&amount,
		&status,
	)

	if errors.Is(err, sql.ErrNoRows) {
		return errors.New("payout reference not found")
	}

	if err != nil {
		return err
	}

	if status == "SUCCESS" {
		return tx.Commit()
	}

	_, err = tx.ExecContext(
		ctx,
		`UPDATE wallets
		 SET reserved_kobo = reserved_kobo - $1,
		     updated_at = NOW()
		 WHERE user_id = $2
		   AND currency = 'NGN'`,
		amount,
		userID,
	)

	if err != nil {
		return err
	}

	_, err = tx.ExecContext(
		ctx,
		`INSERT INTO ledger_entries
			(id,user_id,kind,amount_kobo,reference,created_at)
		 VALUES ($1,$2,'PAYOUT',$3,$4,NOW())`,
		uuid.NewString(),
		userID,
		-amount,
		reference,
	)

	if err != nil {
		return err
	}

	_, err = tx.ExecContext(
		ctx,
		`UPDATE payouts
		 SET status = 'SUCCESS',
		     provider_status = 'success',
		     provider_response = $1,
		     updated_at = NOW()
		 WHERE reference = $2`,
		providerResponse,
		reference,
	)

	if err != nil {
		return err
	}

	return tx.Commit()
}

func (a *App) failPayoutByReference(
	ctx context.Context,
	reference string,
	reason string,
) error {
	tx, err := a.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return err
	}

	defer tx.Rollback()

	var userID string
	var amount int64
	var status string

	err = tx.QueryRowContext(
		ctx,
		`SELECT user_id,amount_kobo,status
		 FROM payouts
		 WHERE reference = $1
		 FOR UPDATE`,
		reference,
	).Scan(
		&userID,
		&amount,
		&status,
	)

	if errors.Is(err, sql.ErrNoRows) {
		return errors.New("payout reference not found")
	}

	if err != nil {
		return err
	}

	if status == "SUCCESS" || status == "FAILED" || status == "REVERSED" {
		return tx.Commit()
	}

	_, err = tx.ExecContext(
		ctx,
		`UPDATE wallets
		 SET available_kobo = available_kobo + $1,
		     reserved_kobo = reserved_kobo - $1,
		     updated_at = NOW()
		 WHERE user_id = $2
		   AND currency = 'NGN'`,
		amount,
		userID,
	)

	if err != nil {
		return err
	}

	_, err = tx.ExecContext(
		ctx,
		`UPDATE payouts
		 SET status = CASE
		              WHEN $1 = 'transfer.reversed'
		              THEN 'REVERSED'
		              ELSE 'FAILED'
		              END,
		     provider_status = $1,
		     failure_reason = $1,
		     updated_at = NOW()
		 WHERE reference = $2`,
		reason,
		reference,
	)

	if err != nil {
		return err
	}

	return tx.Commit()
}

func (a *App) failPayout(
	ctx context.Context,
	payoutID string,
	reason string,
) error {
	tx, err := a.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return err
	}

	defer tx.Rollback()

	var userID string
	var amount int64
	var status string

	err = tx.QueryRowContext(
		ctx,
		`SELECT user_id,amount_kobo,status
		 FROM payouts
		 WHERE id = $1
		 FOR UPDATE`,
		payoutID,
	).Scan(&userID, &amount, &status)

	if err != nil {
		return err
	}

	if status == "FAILED" || status == "SUCCESS" {
		return tx.Commit()
	}

	_, err = tx.ExecContext(
		ctx,
		`UPDATE wallets
		 SET available_kobo = available_kobo + $1,
		     reserved_kobo = reserved_kobo - $1,
		     updated_at = NOW()
		 WHERE user_id = $2
		   AND currency = 'NGN'`,
		amount,
		userID,
	)

	if err != nil {
		return err
	}

	_, err = tx.ExecContext(
		ctx,
		`UPDATE payouts
		 SET status = 'FAILED',
		     failure_reason = $1,
		     updated_at = NOW()
		 WHERE id = $2`,
		reason,
		payoutID,
	)

	if err != nil {
		return err
	}

	return tx.Commit()
}

func (a *App) markPayoutUnknown(
	ctx context.Context,
	payoutID string,
	reason string,
) error {
	_, err := a.db.ExecContext(
		ctx,
		`UPDATE payouts
		 SET status = 'UNKNOWN',
		     failure_reason = $1,
		     updated_at = NOW()
		 WHERE id = $2
		   AND status = 'PROCESSING'`,
		reason,
		payoutID,
	)

	return err
}
