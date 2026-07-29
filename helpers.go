package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html/template"
	"math/big"
	"net/http"
	"net/smtp"
	"os"
	"time"
	"unicode/utf8"
)

const (
	otpExpiry      = 15 * time.Minute
	otpMaxAttempts = 5
	minPasswordLen = 8
)

func respondJSON(w http.ResponseWriter, status int, data map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func hashOTP(code string) (string, error) {
	secret := os.Getenv("OTP_SECRET")
	if secret == "" {
		return "", errors.New("OTP_SECRET missing")
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(code))

	return hex.EncodeToString(mac.Sum(nil)), nil
}

func validatePassword(password string) error {
	if utf8.RuneCountInString(password) < minPasswordLen {
		return errors.New("password must be at least 8 characters")
	}
	return nil
}

func GenerateOTPCode() (string, error) {
	code := ""

	for i := 0; i < 6; i++ {
		number, err := rand.Int(
			rand.Reader,
			big.NewInt(10),
		)

		if err != nil {
			return "", err
		}

		code += number.String()
	}

	return code, nil
}

func sendEmail(
	to string,
	username string,
	code string,
	tmpl_file string,
	subject string,
) error {
	tmpl, err := template.ParseFiles(tmpl_file)

	if err != nil {
		return err
	}

	emailData := EmailData{
		Username: username,
		Code:     code,
	}

	var body bytes.Buffer

	err = tmpl.Execute(&body, emailData)

	if err != nil {
		return err
	}

	from := os.Getenv("SENDER")
	password := os.Getenv("PASSWORD_SMTP")

	if from == "" || password == "" {
		return errors.New("SMTP bilgileri eksik")
	}

	auth := smtp.PlainAuth(
		"",
		from,
		password,
		"smtp.gmail.com",
	)

	message := []byte(
		"Subject: " + subject + "\r\n" +
			"Content-Type: text/html; charset=UTF-8\r\n" +
			"\r\n" +
			body.String(),
	)

	return smtp.SendMail(
		"smtp.gmail.com:587",
		auth,
		from,
		[]string{to},
		message,
	)
}

func randomToken() (string, error) {
	b := make([]byte, 32)

	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(b), nil
}
