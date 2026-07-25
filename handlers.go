package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"
)

func register(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var user Register
	ctx := r.Context()

	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)

		json.NewEncoder(w).Encode(map[string]any{
			"error":   "Invalid JSON Data",
			"message": err.Error(),
		})

		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword(
		[]byte(user.Password),
		bcrypt.DefaultCost,
	)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)

		json.NewEncoder(w).Encode(map[string]any{
			"error":   "Bcrypt hashing error",
			"message": err.Error(),
		})

		return
	}

	// Transaction başlat
	tx, err := db.Begin(ctx)

	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)

		json.NewEncoder(w).Encode(map[string]any{
			"error":   "Transaction error",
			"message": err.Error(),
		})

		return
	}

	// Herhangi bir hata olursa rollback
	defer tx.Rollback(ctx)

	var id int

	err = tx.QueryRow(
		ctx,
		`
		INSERT INTO users (username, email, password)
		VALUES ($1, $2, $3)
		ON CONFLICT DO NOTHING
		RETURNING id
		`,
		user.Username,
		user.Email,
		string(hashedPassword),
	).Scan(&id)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			w.WriteHeader(http.StatusConflict)

			json.NewEncoder(w).Encode(map[string]any{
				"error":   "User already exists",
				"message": "Username or email is already registered",
			})

			return
		}

		w.WriteHeader(http.StatusInternalServerError)

		json.NewEncoder(w).Encode(map[string]any{
			"error":   "User registration failed",
			"message": err.Error(),
		})

		return
	}

	code, err := GenerateOTPCode()

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)

		json.NewEncoder(w).Encode(map[string]any{
			"error":   "Generate OTP Code",
			"message": err.Error(),
		})

		return
	}

	otp_secret := os.Getenv("OTP_SECRET")

	if otp_secret == "" {
		log.Fatal("OTP Secret missing .env")
	}

	mac := hmac.New(sha256.New, []byte(otp_secret))

	mac.Write([]byte(code))

	codeHash := mac.Sum(nil)

	if hex.EncodeToString(codeHash) == "" {
		w.WriteHeader(http.StatusInternalServerError)

		json.NewEncoder(w).Encode(map[string]any{
			"error": "OTP Code Hash error",
		})

		return
	}

	// OTP'yi database'e kaydet
	_, err = tx.Exec(
		ctx,
		`
		INSERT INTO email_verifications
		(user_id, code_hash, expires_at)
		VALUES ($1, $2, $3)
		`,
		id,
		hex.EncodeToString(codeHash),
		time.Now().Add(15*time.Minute),
	)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)

		json.NewEncoder(w).Encode(map[string]any{
			"error":   "Database insert error",
			"message": err.Error(),
		})

		return
	}

	// Her şey başarılıysa transaction'ı kaydet
	err = tx.Commit(ctx)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)

		json.NewEncoder(w).Encode(map[string]any{
			"error":   "Transaction commit error",
			"message": err.Error(),
		})

		return
	}

	go func() {
		err := sendEmail(
			user.Email,
			user.Username,
			code,
		)

		if err != nil {
			log.Println("email gönderilemedi:", err)
		}
	}()

	w.WriteHeader(http.StatusCreated)

	json.NewEncoder(w).Encode(map[string]any{
		"message":  "User created",
		"otp_sent": true,
		"id":       id,
	})
}

func verify_email(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req VerifyEmail

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)

		json.NewEncoder(w).Encode(map[string]any{
			"error": "Invalid JSON",
		})
		return
	}

	var (
		codeHash  string
		expiresAt time.Time
		attempts  int
	)

	err = db.QueryRow(
		ctx,
		`SELECT code_hash, expires_at, attempts
		FROM email_verifications
		WHERE user_id= $1
		`,
		req.UserID,
	).Scan(&codeHash, &expiresAt, &attempts)

	if errors.Is(err, pgx.ErrNoRows) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)

		json.NewEncoder(w).Encode(map[string]any{
			"error":   "OTP not found",
			"message": err.Error(),
		})

		return
	}

	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)

		json.NewEncoder(w).Encode(map[string]any{
			"error":   "Database error",
			"message": err.Error(),
		})
		return
	}

	if time.Now().After(expiresAt) {
		_, err = db.Exec(
			ctx,
			`
			DELETE FROM email_verifications
			WHERE user_id=$1
			`,
			req.UserID,
		)

		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)

			json.NewEncoder(w).Encode(map[string]any{
				"error":   "Database error",
				"message": err.Error(),
			})

			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)

		json.NewEncoder(w).Encode(map[string]any{
			"error": "OTP Code has expired",
		})
		return
	}

	if attempts >= 5 {
		_, err = db.Exec(
			ctx,
			`
			DELETE FROM email_verifications
			WHERE user_id=$1
			`,
			req.UserID,
		)

		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)

			json.NewEncoder(w).Encode(map[string]any{
				"error":   "Database delete error",
				"message": err.Error(),
			})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)

		json.NewEncoder(w).Encode(map[string]any{
			"error": "Trial limit exceeded, Request new OTP Code",
		})
		return
	}

	secret := os.Getenv("OTP_SECRET")

	if secret == "" {
		log.Fatal("OTP_SECRET not found")
	}

	mac := hmac.New(
		sha256.New,
		[]byte(secret),
	)

	mac.Write([]byte(req.Code))

	userCodeHash := hex.EncodeToString(mac.Sum(nil))

	if userCodeHash == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)

		json.NewEncoder(w).Encode(map[string]any{
			"error": "OTP Code Hash Error",
		})
		return
	}

	// OTP yanlış mı?
	if userCodeHash != codeHash {
		_, err = db.Exec(
			ctx,
			`
			UPDATE email_verifications
			SET attempts = attempts + 1
			WHERE user_id = $1
			`,
			req.UserID,
		)

		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)

			json.NewEncoder(w).Encode(map[string]any{
				"error":   "Database error",
				"message": err.Error(),
			})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)

		json.NewEncoder(w).Encode(map[string]any{
			"error": "OTP code is wrong",
		})
		return
	}

	// Email'i doğrula
	_, err = db.Exec(
		ctx,
		`
		UPDATE users
		SET email_verified = TRUE
		WHERE id = $1
		`,
		req.UserID,
	)

	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)

		json.NewEncoder(w).Encode(map[string]any{
			"error": "Email could not be verified",
		})

		return
	}

	// OTP'yi sil
	_, err = db.Exec(
		ctx,
		`
		DELETE FROM email_verifications
		WHERE user_id = $1
		`,
		req.UserID,
	)

	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)

		json.NewEncoder(w).Encode(map[string]any{
			"error": "OTP silinemedi",
		})

		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	json.NewEncoder(w).Encode(map[string]any{
		"message": "Email başarıyla doğrulandı",
	})
}

func login(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	ctx := r.Context()

	var user Login

	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)

		json.NewEncoder(w).Encode(map[string]any{
			"error":   "Invalid JSON",
			"message": err.Error(),
		})

		return
	}

	var (
		userID        int
		passwordDB    string
		emailVerified bool
	)

	err = db.QueryRow(
		ctx,
		`
		SELECT id,password,email_verified
		FROM users
		WHERE username=$1
		`,
		user.Username,
	).Scan(
		&userID,
		&passwordDB,
		&emailVerified,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		w.WriteHeader(http.StatusUnauthorized)

		json.NewEncoder(w).Encode(map[string]any{
			"error":   "Username or password is wrong",
			"message": "please retry",
		})
		return
	}

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)

		json.NewEncoder(w).Encode(map[string]any{
			"error":   "Database error",
			"message": err.Error(),
		})
		return
	}

	if emailVerified == false {
		w.WriteHeader(http.StatusUnauthorized)

		json.NewEncoder(w).Encode(map[string]any{
			"error":   "Your email is not verified",
			"message": "Please verify your email first",
		})
		return
	}

	err = bcrypt.CompareHashAndPassword(
		[]byte(passwordDB),
		[]byte(user.Password),
	)

	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)

		json.NewEncoder(w).Encode(map[string]any{
			"error": "Invalid credentials",
		})

		return
	}

	claims := Claims{
		UserID: userID,

		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(
				time.Now().Add(15 * time.Minute),
			),

			IssuedAt: jwt.NewNumericDate(
				time.Now(),
			),
		},
	}

	access := jwt.NewWithClaims(
		jwt.SigningMethodHS256,
		claims,
	)

	secret := os.Getenv("JWT_SECRET")

	if secret == "" {
		log.Fatal("JWT Secret missing")
	}

	accessToken, err := access.SignedString(
		[]byte(secret),
	)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)

		json.NewEncoder(w).Encode(map[string]any{
			"error":   "Create JWT error",
			"message": err.Error(),
		})

		return
	}

	randomToken, err := randomToken()

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)

		json.NewEncoder(w).Encode(map[string]any{
			"error":   "Generate Random token error",
			"message": err.Error(),
		})

		return
	}

	h := sha256.New()

	h.Write([]byte(randomToken))

	refreshToken := hex.EncodeToString(h.Sum(nil))

	if refreshToken == "" {
		w.WriteHeader(http.StatusInternalServerError)

		json.NewEncoder(w).Encode(map[string]any{
			"error": "Generate Refresh token error",
		})
		return
	}

	_, err = db.Exec(
		ctx,
		`
		INSERT INTO refresh_tokens
		(user_id,token,expires_at)
		VALUES($1, $2, $3)
		`,
		userID,
		refreshToken,
		time.Now().Add(
			time.Hour*24*30,
		),
	)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)

		json.NewEncoder(w).Encode(map[string]any{
			"error":   "refresh token DB error",
			"message": err.Error(),
		})
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{
		"login":         true,
		"username":      user.Username,
		"access_token":  accessToken,
		"refresh_token": randomToken, // Only tests

	})

}

func refresh(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	ctx := r.Context()
	var req RefreshRequest

	err := json.NewDecoder(r.Body).Decode(&req)

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)

		json.NewEncoder(w).Encode(map[string]any{
			"error":   "Invalid JSON",
			"message": err.Error(),
		})
		return
	}

	var (
		userID int
		exp    time.Time
	)

	refreshHash := sha256.Sum256([]byte(req.RefreshToken))
	refreshHashStr := hex.EncodeToString(refreshHash[:])

	err = db.QueryRow(
		ctx,
		`
		SELECT user_id,expires_at
		FROM refresh_tokens
		WHERE token=$1
		`,
		refreshHashStr,
	).Scan(
		&userID,
		&exp,
	)

	if err != nil {
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(map[string]any{
			"error":   "Refresh Token is invalid",
			"message": err.Error(),
		})
		return
	}

	var username string

	err = db.QueryRow(
		ctx,
		`
		SELECT username 
		FROM users
		WHERE id=$1
		`,
		userID,
	).Scan(&username)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)

		json.NewEncoder(w).Encode(map[string]any{
			"error":   "Database error",
			"message": err.Error(),
		})

		return
	}

	if time.Now().After(exp) {
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(map[string]any{
			"error": "Refresh token has expired",
		})

		return
	}

	_, err = db.Exec(
		ctx,
		`
		DELETE FROM refresh_tokens
		WHERE token=$1
		`,
		refreshHashStr,
	)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{
			"error": "eski refresh token silinemedi",
		})
		return
	}

	// yeni access token
	claims := Claims{
		UserID: userID,

		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(
				time.Now().Add(15 * time.Minute),
			),
			IssuedAt: jwt.NewNumericDate(
				time.Now(),
			),
		},
	}

	token := jwt.NewWithClaims(
		jwt.SigningMethodHS256,
		claims,
	)

	accessToken, err := token.SignedString(
		[]byte(os.Getenv("JWT_SECRET")),
	)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{
			"error":   "JWT oluşturulamadı",
			"message": err.Error(),
		})
		return
	}

	// yeni refresh token
	newRefreshToken, err := randomToken()

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{
			"error":   "Refresh token oluşturulamadı",
			"message": err.Error(),
		})
		return
	}

	h := sha256.New()

	h.Write([]byte(newRefreshToken))

	newHash := h.Sum(nil)

	newHashStr := hex.EncodeToString(newHash[:])

	_, err = db.Exec(
		ctx,
		`
		INSERT INTO refresh_tokens
		(user_id, token, expires_at)
		VALUES($1, $2, $3)
		`,
		userID,
		newHashStr,
		time.Now().Add(30*24*time.Hour),
	)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{
			"error":   "Refresh token DB'ye kaydedilemedi",
			"message": err.Error(),
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]any{
		"access_token":  accessToken,
		"refresh_token": newRefreshToken,
	})

}

func get_posts(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	ctx := r.Context()
	rows, err := db.Query(
		ctx,
		`
		SELECT id, user_id, username, title, content, created_at
		FROM posts
		ORDER BY id DESC
		LIMIT 50
		`,
	)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{
			"error":   "Database error",
			"message": err.Error(),
		})

		return
	}
	defer rows.Close()

	posts := []Post{}

	for rows.Next() {
		var post Post

		err := rows.Scan(
			&post.ID,
			&post.UserID,
			&post.Username,
			&post.Title,
			&post.Content,
			&post.CreatedAt,
		)

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]any{
				"error":   "Failed to scan post",
				"message": err.Error(),
			})

			return
		}

		posts = append(posts, post)
	}

	if err := rows.Err(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{
			"error":   "Failed to iterate posts",
			"message": err.Error(),
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]any{
		"posts": posts,
	})
}

func create_post(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	ctx := r.Context()
	var req CreatePostRequest

	err := json.NewDecoder(r.Body).Decode(&req)

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)

		json.NewEncoder(w).Encode(map[string]any{
			"error": "Invalid JSON",
		})
		return
	}

	userID, exists := r.Context().Value(userIDKey).(int)

	if !exists {
		w.WriteHeader(http.StatusUnauthorized)

		json.NewEncoder(w).Encode(map[string]any{
			"error": "Unauthorized",
		})

		return
	}

	var username string

	err = db.QueryRow(
		ctx,
		`
		SELECT username
		FROM users
		WHERE id=$1
		`,
		userID,
	).Scan(&username)

	if errors.Is(err, pgx.ErrNoRows) {
		w.WriteHeader(http.StatusNotFound)

		json.NewEncoder(w).Encode(map[string]any{
			"error": "User not found",
		})
		return
	}

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)

		json.NewEncoder(w).Encode(map[string]any{
			"error":   "Database error",
			"message": err.Error(),
		})
		return
	}

	var postID int

	err = db.QueryRow(
		ctx,
		`
		INSERT INTO posts(
			user_id, username ,title, content
		)
		VALUES ($1, $2, $3, $4)
		RETURNING id
		`,
		userID,
		username,
		req.Title,
		req.Content,
	).Scan(&postID)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)

		json.NewEncoder(w).Encode(map[string]any{
			"error":   "Database insert error",
			"message": err.Error(),
		})

		return
	}

	w.WriteHeader(http.StatusCreated)

	json.NewEncoder(w).Encode(map[string]any{
		"message": "Post created",
		"post_id": postID,
	})
}

func get_user_posts(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	ctx := r.Context()
	username := chi.URLParam(r, "username")

	rows, err := db.Query(
		ctx,
		`
		SELECT id, user_id, username ,title, content, created_at
		FROM posts
		WHERE username=$1
		ORDER BY created_at DESC
		`,
		username,
	)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)

		json.NewEncoder(w).Encode(map[string]any{
			"error":   "Database error",
			"message": err.Error(),
		})

		return
	}

	defer rows.Close()

	posts := []Post{}

	for rows.Next() {
		var post Post

		err := rows.Scan(
			&post.ID,
			&post.UserID,
			&post.Username,
			&post.Title,
			&post.Content,
			&post.CreatedAt,
		)

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]any{
				"error":   "Failed to scan post",
				"message": err.Error(),
			})

			return
		}

		posts = append(posts, post)
	}

	if err := rows.Err(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{
			"error":   "Failed to iterate posts",
			"message": err.Error(),
		})
		return
	}

	w.WriteHeader(http.StatusOK)

	json.NewEncoder(w).Encode(map[string]any{
		"posts": posts,
	})
}

func create_comment(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	ctx := r.Context()
	var req CreateComment

	err := json.NewDecoder(r.Body).Decode(&req)

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)

		json.NewEncoder(w).Encode(map[string]any{
			"error":   "Invalid JSON",
			"message": err.Error(),
		})

		return
	}

	userID, exists := r.Context().Value(userIDKey).(int)

	if !exists {
		w.WriteHeader(http.StatusUnauthorized)

		json.NewEncoder(w).Encode(map[string]any{
			"error":   "user not login",
			"message": "Please login first",
		})

		return
	}

	var username string

	err = db.QueryRow(
		ctx,
		`
		SELECT username
		FROM posts
		WHERE id=$1
		`,
		userID,
	).Scan(&username)

	if errors.Is(err, pgx.ErrNoRows) {
		w.WriteHeader(http.StatusUnauthorized)

		json.NewEncoder(w).Encode(map[string]any{
			"error": "User not found",
		})
		return
	}

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)

		json.NewEncoder(w).Encode(map[string]any{
			"error":   "Database error",
			"message": err.Error(),
		})
		return
	}

	err = db.QueryRow(
		ctx,
		`
		SELECT EXISTS (
			SELECT 1
			FROM users
			WHERE id = $1
		)
		`,
		req.PostID,
	).Scan(&exists)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)

		json.NewEncoder(w).Encode(map[string]any{
			"error":   "Database error",
			"message": err.Error(),
		})
		return
	}

	if !exists {
		w.WriteHeader(http.StatusNotFound)

		json.NewEncoder(w).Encode(map[string]any{
			"error": "Post not found",
		})

		return
	}

	_, err = db.Exec(
		ctx,
		`
		INSERT INTO comments(
			post_id, user_id, username, content	
		)
		VALUES ($1, $2, $3, $4)
		`,
		req.PostID,
		userID,
		username,
		req.Content,
	)
}

func get_post_comments(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	ctx := r.Context()
	postID, err := strconv.Atoi(chi.URLParam(r, "post_id"))

	rows, err := db.Query(
		ctx,
		`
		SELECT id, user_id, username, content, created_at
		FROM comments
		WHERE post_id=$1
		ORDER BY created_at DESC
		`,
		postID,
	)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)

		json.NewEncoder(w).Encode(map[string]any{
			"error":   "Database error",
			"message": err.Error(),
		})

		return
	}

	defer rows.Close()

	comments := []Comments{}

	for rows.Next() {
		var comment Comments

		err := rows.Scan(
			&comment.ID,
			&comment.UserID,
			&comment.Username,
			&comment.Content,
			&comment.CreatedAt,
		)

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]any{
				"error":   "Failed to scan post",
				"message": err.Error(),
			})

			return
		}

		comments = append(comments, comment)
	}

	if err := rows.Err(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{
			"error":   "Failed to iterate comments",
			"message": err.Error(),
		})
		return
	}

	w.WriteHeader(http.StatusOK)

	json.NewEncoder(w).Encode(map[string]any{
		"comments": comments,
	})
}
