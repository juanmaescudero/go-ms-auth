package mails

import (
	"fmt"
	"net/smtp"
)

func ConfirmationMail(email string, token string) {
	from := "hola@gestionclinica.es"
	password := "Gestionclinica.614"

	// Receiver email address.
	to := []string{
		email,
	}

	// smtp server configuration.
	smtpHost := "smtp.ionos.es"
	smtpPort := "25"

	// Authentication.
	auth := smtp.PlainAuth("", from, password, smtpHost)

	message := []byte("Este es un correo de ejemplo sin plantilla HTML." + email + " " + token)

	// Enviar correo
	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, from, to, message)
	if err != nil {
		fmt.Println("Error al enviar el correo:", err)
		return
	}

	fmt.Println("Correo enviado correctamente.")
}
