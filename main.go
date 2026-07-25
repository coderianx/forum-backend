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
			auth.With(RateLimitByIP(3, time.Minute)).Post(
				"/register", register,
			)
			auth.With(RateLimitByIP(3, time.Minute)).Post(
				"/verify-email", verify_email,
			)
			auth.With(RateLimitByIP(3, time.Minute)).Post(
				"/refresh", refresh,
			)
		})
		api.Get("/posts", get_posts)
		api.With(authMiddleware, RateLimitByIP(3, time.Minute)).Post(
			"/post", create_post,
		)
		api.Get("/posts/{username}", get_user_posts)
		api.With(authMiddleware, RateLimitByIP(3, time.Minute)).Post(
			"/comment", create_comment,
		)
		api.Get("/post/{post_id}/comments", get_post_comments)
	})

	http.ListenAndServe(":8080", r)
}
