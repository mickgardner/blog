package main

import (
	"github.com/gofiber/fiber/v2"
	"log"
	"time"
)

// GetTemplateData returns base template data including current user
func (a *App) GetTemplateData(c *fiber.Ctx, data fiber.Map) fiber.Map {
	if data == nil {
		data = fiber.Map{}
	}
	
	// Add user from locals
	user := c.Locals("User")
	data["User"] = user
	data["IsAuthenticated"] = user != nil
	
	return data
}

func (a *App) IndexHandler(c *fiber.Ctx) error {
	articles, err := a.GetPublishedArticles()
	if err != nil {
		return fiber.ErrInternalServerError
	}
	return c.Render("index", a.GetTemplateData(c, fiber.Map{
		"Title":    "Blog",
		"Articles": articles,
	}), "layouts/base")
}

func (a *App) ArticleHandler(c *fiber.Ctx) error {
	slug := c.Params("slug")
	article, err := a.GetArticle(slug)
	if err != nil {
		return fiber.ErrNotFound
	}
	return c.Render("article", a.GetTemplateData(c, fiber.Map{
		"Title":   "<blog keywords and title>",
		"Message": "Blog Article",
		"Article": article,
	}), "layouts/base")
}

func (a *App) AboutHandler(c *fiber.Ctx) error {
	return c.Render("pages/about", a.GetTemplateData(c, fiber.Map{
		"Title":   "About Page",
		"Message": "About Page",
	}), "layouts/base")
}

// Show login form
func (a *App) LoginHandler(c *fiber.Ctx) error {
	return c.Render("auth/login", a.GetTemplateData(c, fiber.Map{
		"Title":      "Login",
		"csrf_token": c.Locals("csrf_token"),
	}), "layouts/base")
}

// Process the login form data - authenticate with email/password
func (a *App) LoginPostHandler(c *fiber.Ctx) error {
	email := c.FormValue("email")
	password := c.FormValue("password")

	if email == "" || password == "" {
		return c.Render("auth/login", fiber.Map{
			"Title":      "Login",
			"csrf_token": c.Locals("csrf_token"),
			"Error":      "Email and password are required",
			"Email":      email,
		}, "layouts/base")
	}

	// Authenticate user
	user, err := a.AuthenticateUser(email, password)
	if err != nil {
		log.Printf("Login attempt failed for %s: %v", email, err)
		return c.Render("auth/login", fiber.Map{
			"Title":      "Login",
			"csrf_token": c.Locals("csrf_token"),
			"Error":      "Invalid email or password",
			"Email":      email,
		}, "layouts/base")
	}

	// Check if email is verified
	if !user.EmailVerified {
		// Generate and send verification code
		verification, err := a.CreateVerificationCode(user.EmailAddress)
		if err != nil {
			return c.Render("auth/login", fiber.Map{
				"Title":      "Login",
				"csrf_token": c.Locals("csrf_token"),
				"Error":      "Failed to send verification code",
				"Email":      email,
			}, "layouts/base")
		}

		// Send verification code via email
		err = a.EmailService.SendVerificationCode(user.EmailAddress, verification.Code)
		if err != nil {
			return c.Render("auth/login", fiber.Map{
				"Title":      "Login",
				"csrf_token": c.Locals("csrf_token"),
				"Error":      "Failed to send verification email",
				"Email":      email,
			}, "layouts/base")
		}

		// Show verification form
		return c.Render("auth/verify", fiber.Map{
			"Title":      "Verify Email",
			"csrf_token": c.Locals("csrf_token"),
			"Email":      user.EmailAddress,
			"Message":    "Please check your email for the verification code",
		}, "layouts/base")
	}

	// Email already verified, log user in directly
	err = a.CreateUserSession(c, user)
	if err != nil {
		log.Printf("Failed to create session: %v", err)
		return c.Render("auth/login", fiber.Map{
			"Title":      "Login",
			"csrf_token": c.Locals("csrf_token"),
			"Error":      "Login successful but session creation failed",
			"Email":      email,
		}, "layouts/base")
	}

	log.Printf("User logged in: %s", user.EmailAddress)
	redirectURL := a.RedirectAfterLogin(c)
	return c.Redirect(redirectURL)
}

// Verify email verification code and complete login
func (a *App) VerifyCodeHandler(c *fiber.Ctx) error {
	email := c.FormValue("email")
	code := c.FormValue("code")

	if email == "" || code == "" {
		return c.Render("auth/verify", fiber.Map{
			"Title":      "Verify Email",
			"csrf_token": c.Locals("csrf_token"),
			"Email":      email,
			"Error":      "Please enter the verification code",
		}, "layouts/base")
	}

	// Verify the code
	_, err := a.VerifyCode(email, code)
	if err != nil {
		log.Printf("Verify Code attempt failed for %s, with error %s", email, err)
		return c.Render("auth/verify", fiber.Map{
			"Title":      "Verify Email",
			"csrf_token": c.Locals("csrf_token"),
			"Email":      email,
			"Error":      "Invalid or expired code",
		}, "layouts/base")
	}

	// Get user and mark email as verified
	user, err := a.GetUserByEmail(email)
	if err != nil {
		log.Printf("User not found for email %s: %v", email, err)
		return c.Render("auth/verify", fiber.Map{
			"Title":      "Verify Email",
			"csrf_token": c.Locals("csrf_token"),
			"Email":      email,
			"Error":      "User not found",
		}, "layouts/base")
	}

	// Mark email as verified
	user.EmailVerified = true
	a.DB.Save(user)

	// Create session and log user in
	err = a.CreateUserSession(c, user)
	if err != nil {
		log.Printf("Failed to create session: %v", err)
		return c.Render("auth/verify", fiber.Map{
			"Title":      "Verify Email",
			"csrf_token": c.Locals("csrf_token"),
			"Email":      email,
			"Error":      "Verification successful but session creation failed",
		}, "layouts/base")
	}

	log.Printf("Email verified and session created for user: %s", user.EmailAddress)
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
	return c.Render("pages/dashboard", a.GetTemplateData(c, fiber.Map{
		"Title": "Dashboard",
	}), "layouts/base")
}

// A profile page for users personal account and login details.
// AUTHENTICATED PAGE
func (a *App) ProfileHandler(c *fiber.Ctx) error {
	user, err := a.GetCurrentUser(c)
	if err != nil {
		return c.Redirect("/login")
	}
	
	// Get article count for this user
	var articleCount int64
	a.DB.Model(&Article{}).Where("author_id = ?", user.ID).Count(&articleCount)
	
	return c.Render("pages/profile", a.GetTemplateData(c, fiber.Map{
		"Title":        "Profile",
		"ArticleCount": articleCount,
	}), "layouts/base")
}

// Show author profile page with their articles
func (a *App) AuthorHandler(c *fiber.Ctx) error {
	authorID := c.Params("id")
	
	// Get the author user
	var author User
	err := a.DB.Where("id = ?", authorID).First(&author).Error
	if err != nil {
		return fiber.ErrNotFound
	}
	
	// Get articles by this author
	var articles []Article
	err = a.DB.Preload("Author").Where("author_id = ? AND published_at IS NOT NULL AND published_at <= ?", authorID, time.Now()).Order("published_at DESC").Find(&articles).Error
	if err != nil {
		return fiber.ErrInternalServerError
	}
	
	return c.Render("author", a.GetTemplateData(c, fiber.Map{
		"Title":    author.FullName + " - Author",
		"Author":   author,
		"Articles": articles,
	}), "layouts/base")
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
	password := c.FormValue("password")
	fullName := c.FormValue("full_name")

	if token == "" || email == "" || password == "" || fullName == "" {
		return c.Render("auth/register", fiber.Map{
			"Title":      "Complete Registration",
			"Token":      token,
			"Email":      email,
			"FullName":   fullName,
			"Error":      "All fields are required",
			"csrf_token": c.Locals("csrf_token"),
		}, "layouts/base")
	}

	// Validate password strength
	if len(password) < 8 {
		return c.Render("auth/register", fiber.Map{
			"Title":      "Complete Registration",
			"Token":      token,
			"Email":      email,
			"FullName":   fullName,
			"Error":      "Password must be at least 8 characters long",
			"csrf_token": c.Locals("csrf_token"),
		}, "layouts/base")
	}

	user, err := a.CompleteRegistration(token, email, password, fullName)
	if err != nil {
		return c.Render("auth/register", fiber.Map{
			"Title":      "Complete Registration",
			"Token":      token,
			"Email":      email,
			"FullName":   fullName,
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
	return c.Render("admin/invite", a.GetTemplateData(c, fiber.Map{
		"Title":      "Send Invitation",
		"csrf_token": c.Locals("csrf_token"),
	}), "layouts/base")
}

// Update user profile information
func (a *App) UpdateProfileHandler(c *fiber.Ctx) error {
	user, err := a.GetCurrentUser(c)
	if err != nil {
		return c.Redirect("/login")
	}
	
	// Get article count for this user
	var articleCount int64
	a.DB.Model(&Article{}).Where("author_id = ?", user.ID).Count(&articleCount)
	
	fullName := c.FormValue("full_name")
	email := c.FormValue("email")
	
	if fullName == "" || email == "" {
		return c.Render("pages/profile", a.GetTemplateData(c, fiber.Map{
			"Title":        "Profile",
			"ArticleCount": articleCount,
			"Error":        "Full name and email are required",
		}), "layouts/base")
	}
	
	// Check if email is already taken by another user
	var existingUser User
	err = a.DB.Where("email_address = ? AND id != ?", email, user.ID).First(&existingUser).Error
	if err == nil {
		return c.Render("pages/profile", a.GetTemplateData(c, fiber.Map{
			"Title":        "Profile",
			"ArticleCount": articleCount,
			"Error":        "Email address is already in use by another account",
		}), "layouts/base")
	}
	
	// Update user information
	user.FullName = fullName
	user.EmailAddress = email
	
	err = a.DB.Save(user).Error
	if err != nil {
		log.Printf("Failed to update user profile: %v", err)
		return c.Render("pages/profile", a.GetTemplateData(c, fiber.Map{
			"Title":        "Profile",
			"ArticleCount": articleCount,
			"Error":        "Failed to update profile. Please try again.",
		}), "layouts/base")
	}
	
	log.Printf("Profile updated for user: %s", user.EmailAddress)
	return c.Render("pages/profile", a.GetTemplateData(c, fiber.Map{
		"Title":        "Profile",
		"ArticleCount": articleCount,
		"Success":      "Profile updated successfully!",
	}), "layouts/base")
}

// Change user password
func (a *App) ChangePasswordHandler(c *fiber.Ctx) error {
	user, err := a.GetCurrentUser(c)
	if err != nil {
		return c.Redirect("/login")
	}
	
	// Get article count for this user
	var articleCount int64
	a.DB.Model(&Article{}).Where("author_id = ?", user.ID).Count(&articleCount)
	
	currentPassword := c.FormValue("current_password")
	newPassword := c.FormValue("new_password")
	confirmPassword := c.FormValue("confirm_password")
	
	if currentPassword == "" || newPassword == "" || confirmPassword == "" {
		return c.Render("pages/profile", a.GetTemplateData(c, fiber.Map{
			"Title":        "Profile",
			"ArticleCount": articleCount,
			"Error":        "All password fields are required",
		}), "layouts/base")
	}
	
	// Verify current password
	err = CheckPassword(currentPassword, user.PasswordHash)
	if err != nil {
		return c.Render("pages/profile", a.GetTemplateData(c, fiber.Map{
			"Title":        "Profile",
			"ArticleCount": articleCount,
			"Error":        "Current password is incorrect",
		}), "layouts/base")
	}
	
	// Check password requirements
	if len(newPassword) < 8 {
		return c.Render("pages/profile", a.GetTemplateData(c, fiber.Map{
			"Title":        "Profile",
			"ArticleCount": articleCount,
			"Error":        "New password must be at least 8 characters long",
		}), "layouts/base")
	}
	
	// Check password confirmation
	if newPassword != confirmPassword {
		return c.Render("pages/profile", a.GetTemplateData(c, fiber.Map{
			"Title":        "Profile",
			"ArticleCount": articleCount,
			"Error":        "New passwords do not match",
		}), "layouts/base")
	}
	
	// Hash new password
	newPasswordHash, err := HashPassword(newPassword)
	if err != nil {
		log.Printf("Failed to hash new password: %v", err)
		return c.Render("pages/profile", a.GetTemplateData(c, fiber.Map{
			"Title":        "Profile",
			"ArticleCount": articleCount,
			"Error":        "Failed to update password. Please try again.",
		}), "layouts/base")
	}
	
	// Update password in database
	user.PasswordHash = newPasswordHash
	err = a.DB.Save(user).Error
	if err != nil {
		log.Printf("Failed to save new password: %v", err)
		return c.Render("pages/profile", a.GetTemplateData(c, fiber.Map{
			"Title":        "Profile",
			"ArticleCount": articleCount,
			"Error":        "Failed to update password. Please try again.",
		}), "layouts/base")
	}
	
	log.Printf("Password changed for user: %s", user.EmailAddress)
	return c.Render("pages/profile", a.GetTemplateData(c, fiber.Map{
		"Title":        "Profile",
		"ArticleCount": articleCount,
		"Success":      "Password changed successfully!",
	}), "layouts/base")
}

// Show forgot password form
func (a *App) ForgotPasswordHandler(c *fiber.Ctx) error {
	return c.Render("auth/forgot-password", fiber.Map{
		"Title":      "Forgot Password",
		"csrf_token": c.Locals("csrf_token"),
	}, "layouts/base")
}

// Process forgot password form and send reset email
func (a *App) ForgotPasswordPostHandler(c *fiber.Ctx) error {
	email := c.FormValue("email")

	if email == "" {
		return c.Render("auth/forgot-password", fiber.Map{
			"Title":      "Forgot Password",
			"csrf_token": c.Locals("csrf_token"),
			"Error":      "Email address is required",
		}, "layouts/base")
	}

	// Create password reset token (this will validate user exists)
	resetToken, err := a.CreatePasswordResetToken(email)
	if err != nil {
		// Don't reveal if user exists or not
		return c.Render("auth/forgot-password", fiber.Map{
			"Title":   "Forgot Password",
			"Message": "If an account with that email exists, you will receive a password reset link",
		}, "layouts/base")
	}

	// Send password reset email
	err = a.EmailService.SendPasswordReset(email, resetToken.Token)
	if err != nil {
		log.Printf("Failed to send password reset email to %s: %v", email, err)
		// Still show success message for security
	}

	return c.Render("auth/forgot-password", fiber.Map{
		"Title":   "Forgot Password",
		"Message": "If an account with that email exists, you will receive a password reset link",
	}, "layouts/base")
}

// Show password reset form
func (a *App) ResetPasswordHandler(c *fiber.Ctx) error {
	token := c.Query("token")
	if token == "" {
		return c.Render("auth/invalid-token", fiber.Map{
			"Title": "Invalid Reset Link",
			"Error": "Invalid or missing reset token",
		}, "layouts/base")
	}

	// Validate token
	_, err := a.ValidatePasswordResetToken(token)
	if err != nil {
		return c.Render("auth/invalid-token", fiber.Map{
			"Title": "Invalid Reset Link",
			"Error": "Invalid or expired reset token",
		}, "layouts/base")
	}

	return c.Render("auth/reset-password", fiber.Map{
		"Title":      "Reset Password",
		"Token":      token,
		"csrf_token": c.Locals("csrf_token"),
	}, "layouts/base")
}

// Process password reset form
func (a *App) ResetPasswordPostHandler(c *fiber.Ctx) error {
	token := c.FormValue("token")
	password := c.FormValue("password")
	confirmPassword := c.FormValue("confirm_password")

	if token == "" || password == "" || confirmPassword == "" {
		return c.Render("auth/reset-password", fiber.Map{
			"Title":      "Reset Password",
			"Token":      token,
			"csrf_token": c.Locals("csrf_token"),
			"Error":      "All fields are required",
		}, "layouts/base")
	}

	if password != confirmPassword {
		return c.Render("auth/reset-password", fiber.Map{
			"Title":      "Reset Password",
			"Token":      token,
			"csrf_token": c.Locals("csrf_token"),
			"Error":      "Passwords do not match",
		}, "layouts/base")
	}

	if len(password) < 8 {
		return c.Render("auth/reset-password", fiber.Map{
			"Title":      "Reset Password",
			"Token":      token,
			"csrf_token": c.Locals("csrf_token"),
			"Error":      "Password must be at least 8 characters long",
		}, "layouts/base")
	}

	// Reset the password
	err := a.ResetPassword(token, password)
	if err != nil {
		return c.Render("auth/reset-password", fiber.Map{
			"Title":      "Reset Password",
			"Token":      token,
			"csrf_token": c.Locals("csrf_token"),
			"Error":      "Failed to reset password: " + err.Error(),
		}, "layouts/base")
	}

	log.Printf("Password reset successful for token: %s", token[:8]+"...")

	return c.Render("auth/password-reset-success", fiber.Map{
		"Title": "Password Reset Complete",
	}, "layouts/base")
}
