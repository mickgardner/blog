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
}

type SMTPEmailService struct {
	Host      string
	Port      string
	Username  string
	Password  string
	FromEmail string
	FromName  string
}

type MailgunEmailService struct {
	Domain    string
	APIKey    string
	FromEmail string
	FromName  string
}

type ConsoleEmailService struct{}

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
		a.EmailService = SMTPEmailService{
			Host:      a.Config.SMTPHost,
			Port:      a.Config.SMTPPort,
			Username:  a.Config.SMTPUsername,
			Password:  a.Config.SMTPPassword,
			FromEmail: a.Config.SMTPFromEmail,
			FromName:  a.Config.SMTPFromName,
		}
		log.Println("Email service configured: SMTP")
	case "mailgun":
		a.EmailService = MailgunEmailService{
			Domain:    a.Config.MailgunDomain,
			APIKey:    a.Config.MailgunAPIKey,
			FromEmail: a.Config.MailgunFromEmail,
			FromName:  a.Config.MailgunFromName,
		}
		log.Println("Email service configured: Mailgun")
	default:
		a.EmailService = ConsoleEmailService{}
		log.Println("Email service configured: Console(default)")
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

	log.Printf("Email sending initiated for %s", email)
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
			log.Printf("Email attempt %d failed for %s: %v", emailQueue.Attempts, emailQueue.Email, err)

			backoffMinutes := emailQueue.Attempts * emailQueue.Attempts * 5 // 5, 20, 45 minutes
			emailQueue.NextRetry = time.Now().Add(time.Duration(backoffMinutes) * time.Minute)
			emailQueue.Error = err.Error()

			a.DB.Save(emailQueue)

			if emailQueue.Attempts >= emailQueue.MaxAttempts {
				a.notifyAdminEmailFailure(emailQueue)
			}
		} else {
			// Success!
			log.Printf("Email successfully sent to %s after %d attempts", emailQueue.Email, emailQueue.Attempts)
			emailQueue.Sent = true
			emailQueue.Error = ""
			a.DB.Save(emailQueue)
			break
		}
	}
}

func (a *App) notifyAdminEmailFailure(emailQueue *EmailQueue) {
	log.Printf("ADMIN ALERT: Failed to send email to %s after %d attempts. Error: %s", emailQueue.Email, emailQueue.MaxAttempts, emailQueue.Error)

	// TODO: optionally add slack or discord notification.
	//TODO: Email Admin.
	//TODO: Notify Admin within web interface somehow.
	//TODO: Send notification to monitoring system.
}

func (c ConsoleEmailService) SendVerificationCode(email, code string) error {
	log.Printf("===VERIFICATION EMAIL===")
	log.Printf("To: %s", email)
	log.Printf("Your Verification code: %s", code)
	log.Printf("(This code expires in 15 minutes)")
	log.Printf("================================")
	return nil
}

func (c ConsoleEmailService) SendInvitation(email, token string) error {
	log.Printf("===INVITATION EMAIL===")
	log.Printf("To: %s", email)
	//TODO: I can see that if we alter the hostname or port this fails. Need config management of this data just incase.
	log.Printf("Click here to register: http://localhost:3000/register?token=%s", token)
	log.Printf("================================")
	return nil
}

func (c ConsoleEmailService) SendPasswordReset(email, token string) error {
	log.Printf("===PASSWORD RESET EMAIL===")
	log.Printf("To: %s", email)
	log.Printf("Click here to reset your password: http://localhost:3000/reset-password?token=%s", token)
	log.Printf("(This link expires in 1 hour)")
	log.Printf("================================")
	return nil
}

func (s SMTPEmailService) SendVerificationCode(email, code string) error {
	auth := smtp.PlainAuth("", s.Username, s.Password, s.Host)

	subject := "Your Verification Code"
	body := fmt.Sprintf(`Hello!

Your verification code is: %s

This code will expire in 15 minutes.

If you didn't request this code, please ignore this email.

Kind regards,
%s`, code, s.FromName)

	message := fmt.Sprintf("From: %s <%s>\r\n"+
		"To: %s\r\n"+
		"Subject: %s\r\n"+
		"\r\n"+
		"%s\r\n", s.FromName, s.FromEmail, email, subject, body)

	addr := fmt.Sprintf("%s:%s", s.Host, s.Port)
	err := smtp.SendMail(addr, auth, s.FromEmail, []string{email}, []byte(message))
	if err != nil {
		log.Printf("SMTP Error: %v", err)
	}

	log.Printf("SMTP email sent to %s", email)
	return nil
}

func (s SMTPEmailService) SendInvitation(email, token string) error {
	auth := smtp.PlainAuth("", s.Username, s.Password, s.Host)

	//TODO: add config for name of website instead of "our blog" perhaps??
	subject := "You've been Invited to Join our Blog"
	//TODO: There should be config parameters used for domain/port here.
	body := fmt.Sprintf(`
		<h1>You're Invited!</h1>
		<p>Click the link below to complete your registration:</p>
		<a href="http://localhost:3000/register?token=%s">Complete Registration</a>
		<p>This invitation expires in 7 days.</p>
		<p>Kind regards</p>

		<p>%s</p>
		`, token, s.FromName)

	//TODO: Make this into a generic sendEmail() function: It's being used more than once (see above).
	message := fmt.Sprintf("From: %s <%s>\r\n"+
		"To: %s\r\n"+
		"Subject: %s\r\n"+
		"\r\n"+
		"%s\r\n", s.FromName, s.FromEmail, email, subject, body)

	addr := fmt.Sprintf("%s:%s", s.Host, s.Port)
	err := smtp.SendMail(addr, auth, s.FromEmail, []string{email}, []byte(message))
	if err != nil {
		//TODO: Where this fails, we need to notify the admin in some way / or log it in a 'log' table for someone to fix soon.
		log.Printf("SMTP Error: %v", err)

	}
	//TODO: Log this sort of thing too (in a table).
	log.Printf("SMTP email sent to %s", email)
	return nil
}

func (s SMTPEmailService) SendPasswordReset(email, token string) error {
	auth := smtp.PlainAuth("", s.Username, s.Password, s.Host)

	subject := "Password Reset Request"
	body := fmt.Sprintf(`Hello!

We received a request to reset your password. Click the link below to create a new password:

http://localhost:3000/reset-password?token=%s

This link will expire in 1 hour.

If you didn't request this password reset, please ignore this email.

Kind regards,
%s`, token, s.FromName)

	message := fmt.Sprintf("From: %s <%s>\r\n"+
		"To: %s\r\n"+
		"Subject: %s\r\n"+
		"\r\n"+
		"%s\r\n", s.FromName, s.FromEmail, email, subject, body)

	addr := fmt.Sprintf("%s:%s", s.Host, s.Port)
	err := smtp.SendMail(addr, auth, s.FromEmail, []string{email}, []byte(message))
	if err != nil {
		log.Printf("SMTP Error: %v", err)
		return err
	}

	log.Printf("SMTP password reset email sent to %s", email)
	return nil
}

func (m MailgunEmailService) SendVerificationCode(email, code string) error {
	mg := mailgun.NewMailgun(m.Domain, m.APIKey)

	subject := "Your Verification Code"
	body := fmt.Sprintf(`Hello!

Your verification code is: %s

This code will expire in 15 minutes.

If you didn't request this code, please ignore this email.

Kind regards,
%s`, code, m.FromName)
	message := mailgun.NewMessage(
		fmt.Sprintf("%s <%s>", m.FromName, m.FromEmail),
		subject,
		"", // Plain text version, empty for now.
		email,
	)
	message.SetHTML(body)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	_, _, err := mg.Send(ctx, message)
	if err != nil {
		log.Printf("Mailgun Error: %v", err)
		return err
	}

	log.Printf("Mailgun email sent to %s", email)
	return nil
}

// TODO: Fix this.
func (m MailgunEmailService) SendInvitation(email, token string) error {
	mg := mailgun.NewMailgun(m.Domain, m.APIKey)

	//TODO: add config for name of website instead of "our blog" perhaps??
	subject := "You're Invited to Join Our Blog"
	//TODO: There should be config parameters used for domain/port here.
	body := fmt.Sprintf(`
	<h1>You're Invited!</h1>
	<p>Click the link below to complete your registration:</p>
	<a href="http://localhost:3000/register?token=%s">Complete Registration</a>
	<p>This invitation expires in 7 days.</p>

		<p>Kind regards</p>

		<p>%s</p>
	`, token, m.FromName)
	message := mailgun.NewMessage(
		fmt.Sprintf("%s <%s>", m.FromName, m.FromEmail),
		subject,
		"", // Plain text version, empty for now.
		email,
	)
	//TODO: Make this into a generic sendEmail() function: It's being used more than once (see above).
	message.SetHTML(body)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	_, _, err := mg.Send(ctx, message)
	if err != nil {
		//TODO: Where this fails, we need to notify the admin in some way / or log it in a 'log' table for someone to fix soon.
		log.Printf("Mailgun Error: %v", err)
		return err
	}

	//TODO: Log this sort of thing too (in a table).
	log.Printf("Mailgun email sent to %s", email)
	return nil
}

func (m MailgunEmailService) SendPasswordReset(email, token string) error {
	mg := mailgun.NewMailgun(m.Domain, m.APIKey)

	subject := "Password Reset Request"
	body := fmt.Sprintf(`
	<h1>Password Reset Request</h1>
	<p>We received a request to reset your password. Click the link below to create a new password:</p>
	<a href="http://localhost:3000/reset-password?token=%s">Reset Your Password</a>
	<p>This link will expire in 1 hour.</p>
	<p>If you didn't request this password reset, please ignore this email.</p>

	<p>Kind regards</p>
	<p>%s</p>
	`, token, m.FromName)

	message := mailgun.NewMessage(
		fmt.Sprintf("%s <%s>", m.FromName, m.FromEmail),
		subject,
		"", // Plain text version, empty for now.
		email,
	)
	message.SetHTML(body)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	_, _, err := mg.Send(ctx, message)
	if err != nil {
		log.Printf("Mailgun Error: %v", err)
		return err
	}

	log.Printf("Mailgun password reset email sent to %s", email)
	return nil
}
