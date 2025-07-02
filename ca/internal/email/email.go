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
// This constructor reads the required environment variables (RESEND_API_KEY and RESEND_FROM)
// and creates a properly configured email service instance for the certificate authority.
//
// Required Environment Variables:
//   - RESEND_API_KEY: API key for authenticating with the Resend email service
//   - RESEND_FROM: The sender email address that will appear in all outgoing emails
//
// Returns:
//   - *EmailService: Configured email service instance ready for sending emails
//
// Panics:
//   - If either RESEND_API_KEY or RESEND_FROM environment variables are not set
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

// ValidateEmail checks if an email string is in a valid format using regex pattern matching.
//
// Parameters:
//   - address: The email address string to validate
//
// Returns:
//   - bool: true if the email format is valid, false otherwise
func ValidateEmail(address string) bool {
	re := regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[A-Za-z]{2,}$`)
	return re.MatchString(address)
}

// send is an internal method that sends an email with context, subject, and text body.
// This is the core email sending functionality that handles the actual API communication
// with the Resend service, including error handling and logging of successful deliveries.
//
// Parameters:
//   - ctx: Context for controlling request lifecycle and cancellation
//   - to: Recipient email address (must be valid format)
//   - subject: Email subject line
//   - body: Plain text email body content
//
// Returns:
//   - string: Unique email ID from Resend service on successful delivery
//   - error: nil on success, or descriptive error on validation/delivery failure
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
// This is a convenience wrapper around the internal send method.
//
// Parameters:
//   - to: Recipient email address (must be valid format)
//   - subject: Email subject line
//   - body: Plain text email body content
//
// Returns:
//   - string: Unique email ID from Resend service on successful delivery
//   - error: nil on success, or descriptive error on validation/delivery failure
func (e *EmailService) SendEmail(to, subject, body string) (string, error) {
	return e.send(context.Background(), to, subject, body)
}

// SendChallengeEmail sends a cryptographic challenge to the recipient for identity verification.
// It delivers a unique challenge string that the recipient must sign with their private key
// to prove possession of the corresponding public key submitted during identity commitment.
//
// Parameters:
//   - to: Recipient email address (must match the email from identity commitment)
//   - challenge: Base64-encoded cryptographic challenge string that must be signed
//
// Returns:
//   - string: Unique email ID from Resend service on successful delivery
//   - error: nil on success, or descriptive error on validation/delivery failure
func (e *EmailService) SendChallengeEmail(to, challenge string) (string, error) {
	subject := "Verify Your Identity"
	body := "Your challenge is: " + challenge + "\n" + "Sign the challenge with your private key."
	return e.SendEmail(to, subject, body)
}
