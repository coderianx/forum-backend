package main

import (
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/joho/godotenv"
)

func main() {
	err := godotenv.Load()

	if err != nil {
		log.Fatal(".env load error", err.Error())
	}

	connectPostresql()
	createTables()

	r := chi.NewRouter()

	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Route("/api/v1", func(api chi.Router) {
		api.Route("/auth", func(auth chi.Router) {
			auth.Post("/register", register)
			auth.Post("/login", login)
			auth.Post("/verify-email", verify_email)
			auth.Post("/refresh", refresh)
		})
		api.Get("/posts", get_posts)
		api.With(authMiddleware).Post(
			"/post", create_post,
		)
	})

	http.ListenAndServe(":8080", r)
}
