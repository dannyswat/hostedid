package email

import "context"

// Sender is the interface that all email providers must implement.
// This abstraction allows swapping email providers (Gmail, SendGrid, SES, etc.)
// without changing business logic.
type Sender interface {
	// Send sends an email to the specified recipient.
	Send(ctx context.Context, msg Message) error
}

// Message represents an email message to be sent.
type Message struct {
	To       string // recipient email address
	Subject  string // email subject
	HTMLBody string // HTML email body
	TextBody string // plain-text fallback body
}
