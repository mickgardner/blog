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
		return c.Render("auth/verify", fiber.Map{
			"Title":      "Enter Code",
			"csrf_token": c.Locals("csrf_token"),
			"Email":      email,
			"Error":      "Invalid or expired code",
		}, "layouts/base")
	}

	// Get or create user.
	user, err := a.GetOrCreateUser(email, "")
	if err != nil {
		return c.Render("auth/verify", fiber.Map{
			"Title":      "Enter Code",
			"csrf_token": c.Locals("csrf_token"),
			"Error":      "Failed to create user account",
		}, "layouts/base")
	}
	log.Println("User Created: ", user)

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
