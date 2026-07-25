package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type contextKey string

const userIDKey contextKey = "user_id"

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")

		if authHeader == "" {
			http.Error(w, "Authorization header missing", http.StatusUnauthorized)
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)

		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(w, "Invalid authorization format", http.StatusUnauthorized)
			return
		}

		tokenString := parts[1]

		var claims Claims

		token, err := jwt.ParseWithClaims(
			tokenString,
			&claims,
			func(token *jwt.Token) (interface{}, error) {
				if token.Method != jwt.SigningMethodHS256 {
					return nil, errors.New("unexpected signing method")
				}

				return []byte(os.Getenv("JWT_SECRET")), nil
			},
		)

		if err != nil || !token.Valid {
			http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}

		// Gin ctx.Set() yerine request context kullanılır
		ctx := context.WithValue(
			r.Context(),
			userIDKey,
			claims.UserID,
		)

		// Yeni context'e sahip request'i sonraki handler'a gönder
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func RateLimitByIP(
	maxRequests int64,
	duration time.Duration,
) func(http.Handler) http.Handler {

	return func(next http.Handler) http.Handler {

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			// IP adresini porttan ayır
			ip, _, err := net.SplitHostPort(r.RemoteAddr)

			if err != nil {
				// Eğer RemoteAddr port içermiyorsa
				ip = r.RemoteAddr
			}

			key := "rate_limit:" + ip

			// Redis'teki sayacı artır
			count, err := redisClient.Incr(
				r.Context(),
				key,
			).Result()

			if err != nil {
				w.Header().Set(
					"Content-Type",
					"application/json",
				)

				w.WriteHeader(
					http.StatusInternalServerError,
				)

				json.NewEncoder(w).Encode(map[string]any{
					"error": "Rate limit error",
				})

				return
			}

			// İlk istek ise expiration ayarla
			if count == 1 {

				err := redisClient.Expire(
					r.Context(),
					key,
					duration,
				).Err()

				if err != nil {
					w.Header().Set(
						"Content-Type",
						"application/json",
					)

					w.WriteHeader(
						http.StatusInternalServerError,
					)

					json.NewEncoder(w).Encode(map[string]any{
						"error": "Rate limit expiration error",
					})

					return
				}
			}

			// Limit aşıldıysa
			if count > maxRequests {

				// Kaç saniye kaldığını Redis'ten al
				ttl, err := redisClient.TTL(
					r.Context(),
					key,
				).Result()

				if err != nil {
					ttl = duration
				}

				w.Header().Set(
					"Retry-After",
					strconv.FormatInt(
						int64(ttl.Seconds()),
						10,
					),
				)

				w.Header().Set(
					"Content-Type",
					"application/json",
				)

				w.WriteHeader(
					http.StatusTooManyRequests,
				)

				json.NewEncoder(w).Encode(map[string]any{
					"error": "Too Many Requests",
				})

				return
			}

			// Limit aşılmadıysa devam et
			next.ServeHTTP(w, r)
		})
	}
}
