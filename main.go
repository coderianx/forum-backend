package main

import (
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/joho/godotenv"
)

func main() {
	err := godotenv.Load()

	if err != nil {
		log.Fatal(".env load error", err.Error())
	}

	connectRedis()
	connectPostresql()
	createTables()

	r := chi.NewRouter()

	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Route("/api/v1", func(api chi.Router) {
		api.Route("/auth", func(auth chi.Router) {
			// Register (No auth required)
			auth.With(RateLimitByIP(3, time.Minute)).Post(
				"/register", register,
			)
			// Login (No auth required)
			auth.With(RateLimitByIP(5, time.Minute)).Post(
				"/login", login,
			)
			// Verify email (No auth required)
			auth.With(RateLimitByIP(3, time.Minute)).Post(
				"/verify-email", verify_email,
			)
			// Refresh token (No auth required)
			auth.With(RateLimitByIP(3, time.Minute)).Post(
				"/refresh", refresh,
			)
			// Forgot password — send OTP (No auth required)
			auth.With(RateLimitByIP(3, time.Minute)).Post(
				"/forgot-password", forget_password,
			)
			// Confirm forgot password — verify OTP & set new password (No auth required)
			auth.With(RateLimitByIP(3, time.Minute)).Post(
				"/confirm-forgot-password", confirm_forgot_password,
			)
			// Change password (Auth required)
			auth.With(authMiddleware, RateLimitByIP(3, time.Minute)).Post(
				"/change-password", reset_password,
			)

			// Get user info (Auth required)
			auth.With(authMiddleware, RateLimitByIP(3, time.Minute)).Get(
				"/me", get_me,
			)
		})
		// Get posts (No auth required)
		api.Get("/posts", get_posts)
		// Create post (Auth required)
		api.With(authMiddleware, RateLimitByIP(3, time.Minute)).Post(
			"/post", create_post,
		)
		// Get user posts (No auth required)
		api.Get("/posts/{username}", get_user_posts)
		// Create comment (Auth required)
		api.With(authMiddleware, RateLimitByIP(3, time.Minute)).Post(
			"/comment", create_comment,
		)
		// Get post comments (No auth required)
		api.Get("/post/{post_id}/comments", get_post_comments)
		// Search posts (No auth required)
		api.With(RateLimitByIP(10, time.Minute)).Get(
			"/posts/search", searchHandler,
		)
		// Like post (Auth required)
		api.With(authMiddleware, RateLimitByIP(5, time.Minute)).Post(
			"/post/{post_id}/like", like_post,
		)
		// Delete post like (Auth required)
		api.With(authMiddleware, RateLimitByIP(5, time.Minute)).Delete(
			"/post/{post_id}/like", delete_post_like,
		)
		// Get post likes (No auth required)
		api.With(RateLimitByIP(10, time.Minute)).Get(
			"/post/{post_id}/like", get_post_likes,
		)
		// Get user profile (No auth required)
		api.With(RateLimitByIP(10, time.Minute)).Get(
			"/user/profile/{user_id}", get_user_profile,
		)

	})

	http.ListenAndServe(":8080", r)
}
