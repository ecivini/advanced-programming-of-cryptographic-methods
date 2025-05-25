package email

import (
	"context"
	"fmt"
	"log"
	"os"
	"regexp"

	"github.com/resend/resend-go/v2"
)

// EmailService handles sending emails via Resend API.
type EmailService struct {
	Client *resend.Client
	From   string
}

// NewEmailService initializes an EmailService with environment configuration.
func NewEmailService() *EmailService {
	apiKey := os.Getenv("RESEND_API_KEY")
	if apiKey == "" {
		log.Fatal("RESEND_API_KEY environment variable is not set")
	}

	from := os.Getenv("RESEND_FROM")
	if from == "" {
		log.Fatal("RESEND_FROM environment variable is not set")
	}

	client := resend.NewClient(apiKey)

	return &EmailService{
		Client: client,
		From:   from,
	}
}

// ValidateEmail checks if an email string is in a valid format.
func ValidateEmail(address string) bool {
	re := regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[A-Za-z]{2,}$`)
	return re.MatchString(address)
}

// send sends an email with context, subject, and HTML body.
func (e *EmailService) send(ctx context.Context, to, subject, body string) (string, error) {
	if !ValidateEmail(to) {
		return "", fmt.Errorf("invalid email address: %s", to)
	}

	params := &resend.SendEmailRequest{
		From:    e.From,
		To:      []string{to},
		Subject: subject,
		Text:    body,
	}

	// If the client supports context:
	sent, err := e.Client.Emails.SendWithContext(ctx, params)
	if err != nil {
		return "", fmt.Errorf("failed to send email to %s: %w", to, err)
	}

	log.Printf("[+] Email sent to %s | ID: %s", to, sent.Id)
	return sent.Id, nil
}

// SendEmail sends a generic email using Background context.
func (e *EmailService) SendEmail(to, subject, body string) (string, error) {
	return e.send(context.Background(), to, subject, body)
}

// SendVerificationEmail sends a verification link to the recipient.
func (e *EmailService) SendChallengeEmail(to, challenge string) (string, error) {
	subject := "Verify Your Identity"
	body := "Your challenge is: " + challenge + "\n" + "Sign the challenge with your private key."
	return e.SendEmail(to, subject, body)
}
