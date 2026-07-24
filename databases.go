package main

import (
	"context"
	"log"
	"os"

	"github.com/jackc/pgx/v5"
)

var db *pgx.Conn

func connectPostresql() {
	var err error

	DB_URL := os.Getenv("DB_URL")
	if DB_URL == "" {
		log.Fatal("DB_URL .env missing")
	}

	db, err = pgx.Connect(
		context.Background(),
		DB_URL,
	)

	if err != nil {
		log.Fatal("Database connection error", err.Error())
	}

}

func createTables() {
	var err error

	_, err = db.Exec(
		context.Background(),
		`
		CREATE TABLE IF NOT EXISTS users(
			id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
			username TEXT NOT NULL UNIQUE,
			email TEXT NOT NULL UNIQUE,
			password TEXT NOT NULL,
			email_verified BOOLEAN NOT NULL DEFAULT FALSE
		)`,
	)

	if err != nil {
		panic(err)
	}

	_, err = db.Exec(
		context.Background(),
		`
		CREATE TABLE IF NOT EXISTS email_verifications (
			id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
			user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			code_hash TEXT NOT NULL,
			expires_at TIMESTAMP NOT NULL,
			attempts INTEGER NOT NULL DEFAULT 0
		)`,
	)

	if err != nil {
		panic(err)
	}

	_, err = db.Exec(
		context.Background(),
		`
		CREATE TABLE IF NOT EXISTS posts(
			id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
			user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			title TEXT NOT NULL,
			content TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL DEFAULT NOW()
		)`,
	)

	if err != nil {
		panic(err)
	}

	_, err = db.Exec(
		context.Background(),
		`
		CREATE TABLE IF NOT EXISTS refresh_tokens (
			id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
			user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			token TEXT NOT NULL,
			expires_at TIMESTAMP NOT NULL
		)`,
	)

	if err != nil {
		panic(err)
	}
}
