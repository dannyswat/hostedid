package email

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/gmail/v1"
	"google.golang.org/api/option"
)

// GmailConfig holds the configuration for the Gmail email sender.
type GmailConfig struct {
	// CredentialsJSON is the OAuth2 service account or app credentials JSON.
	CredentialsJSON string
	// SenderAddress is the email address emails are sent from.
	SenderAddress string
	// SenderName is the display name for the sender.
	SenderName string
}

// GmailSender implements Sender using the Gmail API.
type GmailSender struct {
	service       *gmail.Service
	senderAddress string
	senderName    string
}

// NewGmailSender creates a new GmailSender.
// It expects a service account credentials JSON with domain-wide delegation,
// or an OAuth2 credentials JSON with a refresh token for the sender mailbox.
func NewGmailSender(ctx context.Context, cfg GmailConfig) (*GmailSender, error) {
	if cfg.CredentialsJSON == "" {
		return nil, fmt.Errorf("gmail: credentials JSON is required")
	}
	if cfg.SenderAddress == "" {
		return nil, fmt.Errorf("gmail: sender address is required")
	}

	// Try service account with domain-wide delegation first
	creds := []byte(cfg.CredentialsJSON)

	// Attempt to parse as service account credentials
	jwtConfig, err := google.JWTConfigFromJSON(creds, gmail.GmailSendScope)
	if err != nil {
		return nil, fmt.Errorf("gmail: failed to parse credentials: %w", err)
	}

	// For service account with domain-wide delegation, impersonate the sender
	jwtConfig.Subject = cfg.SenderAddress

	client := jwtConfig.Client(ctx)

	svc, err := gmail.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, fmt.Errorf("gmail: failed to create service: %w", err)
	}

	return &GmailSender{
		service:       svc,
		senderAddress: cfg.SenderAddress,
		senderName:    cfg.SenderName,
	}, nil
}

// NewGmailSenderWithToken creates a GmailSender using OAuth2 client credentials + refresh token.
// This is useful for personal Gmail accounts without domain-wide delegation.
func NewGmailSenderWithToken(ctx context.Context, clientID, clientSecret, refreshToken, senderAddress, senderName string) (*GmailSender, error) {
	if senderAddress == "" {
		return nil, fmt.Errorf("gmail: sender address is required")
	}

	oauthCfg := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     google.Endpoint,
		Scopes:       []string{gmail.GmailSendScope},
	}

	token := &oauth2.Token{
		RefreshToken: refreshToken,
	}

	client := oauthCfg.Client(ctx, token)

	svc, err := gmail.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, fmt.Errorf("gmail: failed to create service: %w", err)
	}

	return &GmailSender{
		service:       svc,
		senderAddress: senderAddress,
		senderName:    senderName,
	}, nil
}

// Send sends an email via the Gmail API.
func (g *GmailSender) Send(ctx context.Context, msg Message) error {
	from := g.senderAddress
	if g.senderName != "" {
		from = fmt.Sprintf("%s <%s>", g.senderName, g.senderAddress)
	}

	// Build the MIME message
	var emailContent string
	if msg.HTMLBody != "" && msg.TextBody != "" {
		// Multipart alternative (HTML + text)
		boundary := "boundary_hostedid_email"
		emailContent = strings.Join([]string{
			"From: " + from,
			"To: " + msg.To,
			"Subject: " + msg.Subject,
			"MIME-Version: 1.0",
			"Content-Type: multipart/alternative; boundary=" + boundary,
			"",
			"--" + boundary,
			"Content-Type: text/plain; charset=UTF-8",
			"Content-Transfer-Encoding: 7bit",
			"",
			msg.TextBody,
			"",
			"--" + boundary,
			"Content-Type: text/html; charset=UTF-8",
			"Content-Transfer-Encoding: 7bit",
			"",
			msg.HTMLBody,
			"",
			"--" + boundary + "--",
		}, "\r\n")
	} else if msg.HTMLBody != "" {
		emailContent = strings.Join([]string{
			"From: " + from,
			"To: " + msg.To,
			"Subject: " + msg.Subject,
			"MIME-Version: 1.0",
			"Content-Type: text/html; charset=UTF-8",
			"",
			msg.HTMLBody,
		}, "\r\n")
	} else {
		emailContent = strings.Join([]string{
			"From: " + from,
			"To: " + msg.To,
			"Subject: " + msg.Subject,
			"MIME-Version: 1.0",
			"Content-Type: text/plain; charset=UTF-8",
			"",
			msg.TextBody,
		}, "\r\n")
	}

	gmailMsg := &gmail.Message{
		Raw: base64.URLEncoding.EncodeToString([]byte(emailContent)),
	}

	_, err := g.service.Users.Messages.Send("me", gmailMsg).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("gmail: failed to send email: %w", err)
	}

	return nil
}
