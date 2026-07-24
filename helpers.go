package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"html/template"
	"math/big"
	"net/smtp"
	"os"
)

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
) error {
	tmpl, err := template.ParseFiles("template/email.html")

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
		"Subject: Hoşgeldin!\r\n" +
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
