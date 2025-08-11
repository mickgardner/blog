package main

import (
	"github.com/gofiber/fiber/v2"
	"log"
)

func (a *App) IndexHandler(c *fiber.Ctx) error {
	articles, err := a.GetAllArticles()
	if err != nil {
		return fiber.ErrInternalServerError
	}
	return c.Render("index", fiber.Map{
		"Title":    "Blog Homepage",
		"Message":  "Hello Blog",
		"Articles": articles,
	}, "layouts/base")
}

func (a *App) ArticleHandler(c *fiber.Ctx) error {
	slug := c.Params("slug")
	article, err := a.GetArticle(slug)
	if err != nil {
		return fiber.ErrNotFound
	}
	return c.Render("article", fiber.Map{
		"Title":   "<blog keywords and title>",
		"Message": "Blog Article",
		"Article": article,
	}, "layouts/base")
}

func (a *App) AboutHandler(c *fiber.Ctx) error {
	return c.Render("pages/about", fiber.Map{
		"Title":   "About Page",
		"Message": "About Page",
	}, "layouts/base")
}

// Show login form
func (a *App) LoginHandler(c *fiber.Ctx) error {
	return c.Render("auth/login", fiber.Map{
		"Title":      "Login",
		"csrf_token": c.Locals("csrf_token"),
	}, "layouts/base")
}

// Process the login from data and send emails.
func (a *App) RequestCodeHandler(c *fiber.Ctx) error {
	email := c.FormValue("email")
	if email == "" {
		return c.Render("auth/login", fiber.Map{
			"Title":      "Login",
			"csrf_token": c.Locals("csrf_token"),
			"Error":      "Email is required",
		}, "layouts/base")
	}

	// Generate and send verification code.
	verification, err := a.CreateVerificationCode(email)
	if err != nil {
		return c.Render("auth/login", fiber.Map{
			"Title":      "Login",
			"csrf_token": c.Locals("csrf_token"),
			"Error":      "Failed to send verification code",
		}, "layouts/base")
	}

	// Send verification code via email service.
	err = a.EmailService.SendVerificationCode(email, verification.Code)
	if err != nil {
		return c.Render("auth/login", fiber.Map{
			"Title":      "Login",
			"csrf_token": c.Locals("csrf_token"),
			"Error":      "Failed to send email",
		}, "layouts/base")

	}

	// Show verification form.
	return c.Render("auth/verify", fiber.Map{
		"Title":      "Enter Code",
		"csrf_token": c.Locals("csrf_token"),
		"Email":      email,
		"Message":    "Check your email for the verification code",
	}, "layouts/base")
}

// Verify code and log user in.
func (a *App) VerifyCodeHandler(c *fiber.Ctx) error {
	email := c.FormValue("email")
	code := c.FormValue("code")

	// Check if email or code are empty.
	if email == "" || code == "" {
		return c.Render("auth/verify", fiber.Map{
			"Title":      "Enter Code",
			"csrf_token": c.Locals("csrf_token"),
			"Email":      email,
			"Error":      "Please enter the verification code",
		}, "layouts/base")
	}

	// Verify the code
	_, err := a.VerifyCode(email, code)
	if err != nil {
		log.Printf("Verify Code attempt failed for %s, with error %s ", email, err)
		return c.Render("auth/verify", fiber.Map{
			"Title":      "Enter Code",
			"csrf_token": c.Locals("csrf_token"),
			"Email":      email,
			"Error":      "Invalid or expired code",
		}, "layouts/base")
	}

	// Login or fail...
	user, err := a.GetUserByEmail(email)
	if err != nil {
		log.Printf("Login attempt failed for %s: user not found", email)
		return c.Render("auth/verify", fiber.Map{
			"Title":      "Enter Code",
			"csrf_token": c.Locals("csrf_token"),
			"Error":      "Login failed. Please check your details or contact support.",
		}, "layouts/base")
	}
	log.Println("User Created: ", user)

	// Login successful.
	err = a.CreateUserSession(c, user)
	if err != nil {
		log.Printf("Failed to create session: %v", err)
		return c.Render("auth/verify", fiber.Map{
			"Title":      "Enter Code",
			"csrf_token": c.Locals("csrf_token"),
			"Error":      "Login successful but session creation failed",
		}, "layouts/base")

	}

	log.Printf("Session created for user: %s", user.EmailAddress)
	redirectURL := a.RedirectAfterLogin(c)
	return c.Redirect(redirectURL)
}

// Log the user out
func (a *App) LogoutHandler(c *fiber.Ctx) error {
	err := a.DestroySession(c)
	if err != nil {
		log.Printf("Error destroying session: %v", err)
	}

	return c.Redirect("/login")
}

// A Home page dashboard for users when they first login.
// AUTHENTICATED PAGE
func (a *App) DashboardHandler(c *fiber.Ctx) error {
	return c.Render("pages/dashboard", fiber.Map{
		"Title": "Dashboard",
	}, "layouts/base")
}

// A profile page for users personal account and login details.
// AUTHENTICATED PAGE
func (a *App) ProfileHandler(c *fiber.Ctx) error {
	return c.Render("pages/profile", fiber.Map{
		"Title": "Profile",
	}, "layouts/base")
}

func (a *App) SendInviteHandler(c *fiber.Ctx) error {
	user, err := a.GetCurrentUser(c)
	if err != nil || !user.IsAdmin {
		return c.Status(403).Render("errors/403", fiber.Map{
			"Title": "Access Denied",
		}, "layouts/base")
	}

	email := c.FormValue("email")
	//TODO: Is there any more validations required for testing the email address???
	if email == "" {
		return c.Render("admin/invite", fiber.Map{
			"Title":      "Send Invitation",
			"Error":      "Email address is required",
			"csrf_token": c.Locals("csrf_token"),
		}, "layouts/base")
	}

	invitation, err := a.CreateInvitation(user.ID, email)
	if err != nil {
		return c.Render("admin/invite", fiber.Map{
			"Title":      "Send Invitation",
			"Error":      err.Error(),
			"csrf_token": c.Locals("csrf_token"),
		}, "layouts/base")
	}

	err = a.EmailService.SendInvitation(email, invitation.Token)
	if err != nil {
		return c.Render("admin/invite", fiber.Map{
			"Title":      "Send Invitation",
			"Error":      "Failed to send invitation email",
			"csrf_token": c.Locals("csrf_token"),
		}, "layouts/base")
	}

	return c.Render("admin/invite", fiber.Map{
		"Title":      "Send Invitation",
		"Success":    "Invitation sent successfully to " + email,
		"csrf_token": c.Locals("csrf_token"),
	}, "layouts/base")
}

func (a *App) RegisterHandler(c *fiber.Ctx) error {
	token := c.Query("token")
	invitation, err := a.ValidateInvitationToken(token)
	if err != nil {
		return c.Render("auth/invalid-invitation", fiber.Map{
			"Title": "Invalid Invitation",
		}, "layouts/base")
	}

	return c.Render("auth/register", fiber.Map{
		"Title": "Complete Registration",
		"Token": token,
		"Email": invitation.Email,
	}, "layouts/base")
}

func (a *App) ProcessRegistrationHandler(c *fiber.Ctx) error {
	token := c.FormValue("token")
	email := c.FormValue("email")
	fullName := c.FormValue("full_name")

	//TODO: Are these the only validations required? We could do better.
	if token == "" || email == "" || fullName == "" {
		return c.Render("auth/register", fiber.Map{
			"Title":      "Complete Registration",
			"Token":      token,
			"Email":      email,
			"Error":      "All fields are required",
			"csrf_token": c.Locals("csrf_token"),
		}, "layouts/base")
	}

	user, err := a.CompleteRegistration(token, email, fullName)
	if err != nil {
		return c.Render("auth/register", fiber.Map{
			"Title":      "Complete Registration",
			"Token":      token,
			"Email":      email,
			"Error":      "Registration failed: " + err.Error(),
			"csrf_token": c.Locals("csrf_token"),
		}, "layouts/base")
	}

	log.Printf("User registration completed: %s", user.EmailAddress)

	return c.Render("auth/registration-success", fiber.Map{
		"Title": "Registration Complete",
		"Email": user.EmailAddress,
	}, "layouts/base")
}

func (a *App) InviteFormHandler(c *fiber.Ctx) error {
	return c.Render("admin/invite", fiber.Map{
		"Title":      "Send Invitation",
		"csrf_token": c.Locals("csrf_token"),
	}, "layouts/base")
}
