package main

import (
	"context"
	"fmt"
	"gorm.io/gorm"
	"log"
	"time"

	"github.com/mailgun/mailgun-go/v4"
	"net/smtp"
)

type EmailService interface {
	SendVerificationCode(email, code string) error
	SendInvitation(email, token string) error
	SendPasswordReset(email, token string) error
	SetBaseURL(baseURL string)
}

type SMTPEmailService struct {
	Host      string
	Port      string
	Username  string
	Password  string
	FromEmail string
	FromName  string
	BaseURL   string
}

type MailgunEmailService struct {
	Domain    string
	APIKey    string
	FromEmail string
	FromName  string
	BaseURL   string
}

type ConsoleEmailService struct {
	BaseURL string
}

type EmailQueue struct {
	Email       string `gorm:"index"`
	Code        string
	Attempts    int `gorm:"default:0"`
	MaxAttempts int `gorm:"default:3"`
	NextRetry   time.Time
	Sent        bool `gorm:"default:false"`
	Error       string
	gorm.Model
}

func (a *App) SetupEmailService() {
	switch a.Config.EmailService {
	case "smtp":
		a.EmailService = &SMTPEmailService{
			Host:      a.Config.SMTPHost,
			Port:      a.Config.SMTPPort,
			Username:  a.Config.SMTPUsername,
			Password:  a.Config.SMTPPassword,
			FromEmail: a.Config.SMTPFromEmail,
			FromName:  a.Config.SMTPFromName,
			BaseURL:   a.Config.BaseURL,
		}
		LogEmail().Info("Email service configured: SMTP")
	case "mailgun":
		a.EmailService = &MailgunEmailService{
			Domain:    a.Config.MailgunDomain,
			APIKey:    a.Config.MailgunAPIKey,
			FromEmail: a.Config.MailgunFromEmail,
			FromName:  a.Config.MailgunFromName,
			BaseURL:   a.Config.BaseURL,
		}
		LogEmail().Info("Email service configured: Mailgun")
	default:
		a.EmailService = &ConsoleEmailService{
			BaseURL: a.Config.BaseURL,
		}
		LogEmail().Info("Email service configured: Console (default)")
	}
}

func (a *App) SendVerificationEmailAsync(email, code string) {

	go func() {
		emailQueue := EmailQueue{
			Email:       email,
			Code:        code,
			Attempts:    0,
			MaxAttempts: 3,
			NextRetry:   time.Now(),
			Sent:        false,
		}
		a.DB.Create(&emailQueue)
		a.processEmailQueue(&emailQueue)
	}()

	LogEmail().WithField("user", SanitizeEmail(email)).Debug("Email sending initiated")
}

func (a *App) processEmailQueue(emailQueue *EmailQueue) {
	for emailQueue.Attempts < emailQueue.MaxAttempts && !emailQueue.Sent {
		if emailQueue.Attempts > 0 {
			waitTime := time.Until(emailQueue.NextRetry)
			if waitTime > 0 {
				time.Sleep(waitTime)
			}
		}

		emailQueue.Attempts++
		err := a.EmailService.SendVerificationCode(emailQueue.Email, emailQueue.Code)

		if err != nil {
			LogEmail().WithFields(map[string]interface{}{
				"user": SanitizeEmail(emailQueue.Email),
				"attempt": emailQueue.Attempts,
				"error": err.Error(),
			}).Warn("Email sending attempt failed")

			backoffMinutes := emailQueue.Attempts * emailQueue.Attempts * 5 // 5, 20, 45 minutes
			emailQueue.NextRetry = time.Now().Add(time.Duration(backoffMinutes) * time.Minute)
			emailQueue.Error = err.Error()

			a.DB.Save(emailQueue)

			if emailQueue.Attempts >= emailQueue.MaxAttempts {
				a.notifyAdminEmailFailure(emailQueue)
			}
		} else {
			// Success!
			LogEmail().WithFields(map[string]interface{}{
				"user": SanitizeEmail(emailQueue.Email),
				"attempts": emailQueue.Attempts,
			}).Info("Email sent successfully")
			emailQueue.Sent = true
			emailQueue.Error = ""
			a.DB.Save(emailQueue)
			break
		}
	}
}

func (a *App) notifyAdminEmailFailure(emailQueue *EmailQueue) {
	LogEmail().WithFields(map[string]interface{}{
		"user": SanitizeEmail(emailQueue.Email),
		"max_attempts": emailQueue.MaxAttempts,
		"error": emailQueue.Error,
	}).Error("ADMIN ALERT: Email delivery failed after all attempts")

	// For now, we log the failure. In the future, consider:
	// - Adding Slack/Discord webhook notifications
	// - Sending email alerts to admin (requires separate reliable email service)
	// - Adding admin dashboard notifications
	// - Integrating with monitoring systems (Prometheus, DataDog, etc.)

	// Mark this failure in the database for admin review
	emailQueue.Error = "ADMIN_NOTIFIED: " + emailQueue.Error
	a.DB.Save(emailQueue)
}

func (c *ConsoleEmailService) SendVerificationCode(email, code string) error {
	log.Printf("===VERIFICATION EMAIL===")
	log.Printf("To: %s", email)
	log.Printf("Your Verification code: %s", code)
	log.Printf("(This code expires in 15 minutes)")
	log.Printf("================================")
	return nil
}

func (c *ConsoleEmailService) SetBaseURL(baseURL string) {
	c.BaseURL = baseURL
}

func (c *ConsoleEmailService) SendInvitation(email, token string) error {
	log.Printf("===INVITATION EMAIL===")
	log.Printf("To: %s", email)
	log.Printf("Click here to register: %s/register?token=%s", c.BaseURL, token)
	log.Printf("================================")
	return nil
}

func (c *ConsoleEmailService) SendPasswordReset(email, token string) error {
	log.Printf("===PASSWORD RESET EMAIL===")
	log.Printf("To: %s", email)
	log.Printf("Click here to reset your password: %s/reset-password?token=%s", c.BaseURL, token)
	log.Printf("(This link expires in 1 hour)")
	log.Printf("================================")
	return nil
}

// sendSMTPEmail is a generic function for sending emails via SMTP
func (s *SMTPEmailService) sendSMTPEmail(to, subject, body string) error {
	auth := smtp.PlainAuth("", s.Username, s.Password, s.Host)

	message := fmt.Sprintf("From: %s <%s>\r\n"+
		"To: %s\r\n"+
		"Subject: %s\r\n"+
		"\r\n"+
		"%s\r\n", s.FromName, s.FromEmail, to, subject, body)

	addr := fmt.Sprintf("%s:%s", s.Host, s.Port)
	err := smtp.SendMail(addr, auth, s.FromEmail, []string{to}, []byte(message))
	if err != nil {
		LogEmail().WithFields(map[string]interface{}{
			"user": SanitizeEmail(to),
			"error": err.Error(),
		}).Error("SMTP email failed")
		return err
	}

	LogEmail().WithField("user", SanitizeEmail(to)).Info("SMTP email sent successfully")
	return nil
}

func (s *SMTPEmailService) SendVerificationCode(email, code string) error {
	subject := "Your Verification Code"
	body := fmt.Sprintf(`Hello!

Your verification code is: %s

This code will expire in 15 minutes.

If you didn't request this code, please ignore this email.

Kind regards,
%s`, code, s.FromName)

	return s.sendSMTPEmail(email, subject, body)
}

func (s *SMTPEmailService) SendInvitation(email, token string) error {
	subject := "You've been Invited to Join our Blog"
	body := fmt.Sprintf(`
		<h1>You're Invited!</h1>
		<p>Click the link below to complete your registration:</p>
		<a href="%s/register?token=%s">Complete Registration</a>
		<p>This invitation expires in 7 days.</p>
		<p>Kind regards</p>

		<p>%s</p>
		`, s.BaseURL, token, s.FromName)

	return s.sendSMTPEmail(email, subject, body)
}

func (s *SMTPEmailService) SendPasswordReset(email, token string) error {
	subject := "Password Reset Request"
	body := fmt.Sprintf(`Hello!

We received a request to reset your password. Click the link below to create a new password:

%s/reset-password?token=%s

This link will expire in 1 hour.

If you didn't request this password reset, please ignore this email.

Kind regards,
%s`, s.BaseURL, token, s.FromName)

	return s.sendSMTPEmail(email, subject, body)
}

func (s *SMTPEmailService) SetBaseURL(baseURL string) {
	s.BaseURL = baseURL
}

// sendMailgunEmail is a generic function for sending emails via Mailgun
func (m *MailgunEmailService) sendMailgunEmail(to, subject, body string) error {
	mg := mailgun.NewMailgun(m.Domain, m.APIKey)

	message := mailgun.NewMessage(
		fmt.Sprintf("%s <%s>", m.FromName, m.FromEmail),
		subject,
		"", // Plain text version, empty for now.
		to,
	)
	message.SetHTML(body)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	_, _, err := mg.Send(ctx, message)
	if err != nil {
		LogEmail().WithFields(map[string]interface{}{
			"user": SanitizeEmail(to),
			"error": err.Error(),
		}).Error("Mailgun email failed")
		return err
	}

	LogEmail().WithField("user", SanitizeEmail(to)).Info("Mailgun email sent successfully")
	return nil
}

func (m *MailgunEmailService) SendVerificationCode(email, code string) error {
	subject := "Your Verification Code"
	body := fmt.Sprintf(`Hello!

Your verification code is: %s

This code will expire in 15 minutes.

If you didn't request this code, please ignore this email.

Kind regards,
%s`, code, m.FromName)

	return m.sendMailgunEmail(email, subject, body)
}

func (m *MailgunEmailService) SendInvitation(email, token string) error {
	subject := "You're Invited to Join Our Blog"
	body := fmt.Sprintf(`
	<h1>You're Invited!</h1>
	<p>Click the link below to complete your registration:</p>
	<a href="%s/register?token=%s">Complete Registration</a>
	<p>This invitation expires in 7 days.</p>

		<p>Kind regards</p>

		<p>%s</p>
	`, m.BaseURL, token, m.FromName)

	return m.sendMailgunEmail(email, subject, body)
}

func (m *MailgunEmailService) SendPasswordReset(email, token string) error {
	subject := "Password Reset Request"
	body := fmt.Sprintf(`
	<h1>Password Reset Request</h1>
	<p>We received a request to reset your password. Click the link below to create a new password:</p>
	<a href="%s/reset-password?token=%s">Reset Your Password</a>
	<p>This link will expire in 1 hour.</p>
	<p>If you didn't request this password reset, please ignore this email.</p>

	<p>Kind regards</p>
	<p>%s</p>
	`, m.BaseURL, token, m.FromName)

	return m.sendMailgunEmail(email, subject, body)
}

func (m *MailgunEmailService) SetBaseURL(baseURL string) {
	m.BaseURL = baseURL
}
