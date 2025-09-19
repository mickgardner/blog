package main

import (
	"fmt"
	"github.com/gofiber/fiber/v2"
	"html/template"
	"io"
	"log"
	"mime/multipart"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// GetTemplateData returns base template data including current user and navigation
func (a *App) GetTemplateData(c *fiber.Ctx, data fiber.Map) fiber.Map {
	if data == nil {
		data = fiber.Map{}
	}

	// Add user from locals
	user := c.Locals("User")
	data["User"] = user
	data["IsAuthenticated"] = user != nil

	// Add navigation items for header
	navigationItems, err := a.GetActiveNavigationItems()
	if err != nil {
		LogHTTP().WithError(err).Warn("Failed to load navigation items for template")
		navigationItems = []NavigationItem{} // Fallback to empty slice
	}
	data["NavigationItems"] = navigationItems

	return data
}

func (a *App) IndexHandler(c *fiber.Ctx) error {
	articles, err := a.GetPublishedArticles()
	if err != nil {
		LogHTTP().WithError(err).Error("Failed to fetch published articles")
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
		LogHTTP().WithFields(map[string]interface{}{
			"slug": slug,
			"error": err.Error(),
		}).Warn("Article not found")
		return fiber.ErrNotFound
	}

	// Convert markdown body to HTML
	renderedBody, err := MarkdownToHTML(article.Body)
	if err != nil {
		LogHTTP().WithFields(map[string]interface{}{
			"slug": slug,
			"error": err.Error(),
		}).Error("Failed to render markdown")
		// Fallback to raw body if markdown rendering fails
		renderedBody = template.HTML(article.Body)
	}

	// Create a template-friendly version with rendered HTML
	templateArticle := struct {
		*Article
		RenderedBody template.HTML
	}{
		Article:      article,
		RenderedBody: renderedBody,
	}

	return c.Render("article", a.GetTemplateData(c, fiber.Map{
		"Title":   "<blog keywords and title>",
		"Message": "Blog Article",
		"Article": templateArticle,
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
	email := strings.TrimSpace(c.FormValue("email"))
	password := c.FormValue("password")

	if email == "" || password == "" {
		return c.Render("auth/login", fiber.Map{
			"Title":      "Login",
			"csrf_token": c.Locals("csrf_token"),
			"Error":      "Email and password are required",
			"Email":      email,
		}, "layouts/base")
	}

	// Validate email format
	if !isValidEmail(email) {
		return c.Render("auth/login", fiber.Map{
			"Title":      "Login",
			"csrf_token": c.Locals("csrf_token"),
			"Error":      "Please enter a valid email address",
			"Email":      email,
		}, "layouts/base")
	}

	// Authenticate user
	user, err := a.AuthenticateUser(email, password)
	if err != nil {
		LogAuth().WithFields(map[string]interface{}{
			"user": SanitizeEmail(email),
			"error": err.Error(),
		}).Warn("Login attempt failed")
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
		LogAuth().WithError(err).Error("Failed to create session after login")
		return c.Render("auth/login", fiber.Map{
			"Title":      "Login",
			"csrf_token": c.Locals("csrf_token"),
			"Error":      "Login successful but session creation failed",
			"Email":      email,
		}, "layouts/base")
	}

	LogAuth().WithField("user", SanitizeEmail(user.EmailAddress)).Info("User logged in successfully")
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
		LogAuth().WithFields(map[string]interface{}{
			"user": SanitizeEmail(email),
			"error": err.Error(),
		}).Warn("Email verification failed")
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
		LogAuth().WithFields(map[string]interface{}{
			"user": SanitizeEmail(email),
			"error": err.Error(),
		}).Error("User not found during verification")
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
		LogAuth().WithError(err).Error("Failed to create session after verification")
		return c.Render("auth/verify", fiber.Map{
			"Title":      "Verify Email",
			"csrf_token": c.Locals("csrf_token"),
			"Email":      email,
			"Error":      "Verification successful but session creation failed",
		}, "layouts/base")
	}

	LogAuth().WithField("user", SanitizeEmail(user.EmailAddress)).Info("Email verified and session created")
	redirectURL := a.RedirectAfterLogin(c)
	return c.Redirect(redirectURL)
}

// Log the user out
func (a *App) LogoutHandler(c *fiber.Ctx) error {
	err := a.DestroySession(c)
	if err != nil {
		LogAuth().WithError(err).Warn("Error destroying session during logout")
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

// Admin Dashboard Handler
func (a *App) AdminDashboardHandler(c *fiber.Ctx) error {
	// Get dashboard statistics
	var totalArticles, publishedArticles, draftArticles int64
	var totalUsers, activeUsers int64
	
	a.DB.Model(&Article{}).Count(&totalArticles)
	a.DB.Model(&Article{}).Where("published_at IS NOT NULL AND published_at <= ?", time.Now()).Count(&publishedArticles)
	a.DB.Model(&Article{}).Where("published_at IS NULL").Count(&draftArticles)
	a.DB.Model(&User{}).Count(&totalUsers)
	a.DB.Model(&User{}).Where("active = ?", true).Count(&activeUsers)
	
	// Get recent articles
	var recentArticles []Article
	a.DB.Preload("Author").Order("updated_at DESC").Limit(5).Find(&recentArticles)
	
	return c.Render("admin/dashboard", a.GetTemplateData(c, fiber.Map{
		"Title":            "Dashboard",
		"AdminPage":        true,
		"TotalArticles":    totalArticles,
		"PublishedArticles": publishedArticles,
		"DraftArticles":    draftArticles,
		"TotalUsers":       totalUsers,
		"ActiveUsers":      activeUsers,
		"RecentArticles":   recentArticles,
	}), "layouts/admin")
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
		LogHTTP().WithFields(map[string]interface{}{
			"author_id": authorID,
			"error": err.Error(),
		}).Warn("Author not found")
		return fiber.ErrNotFound
	}

	// Get articles by this author
	var articles []Article
	err = a.DB.Preload("Author").Where("author_id = ? AND published_at IS NOT NULL AND published_at <= ?", authorID, time.Now()).Order("published_at DESC").Find(&articles).Error
	if err != nil {
		LogHTTP().WithFields(map[string]interface{}{
			"author_id": authorID,
			"error": err.Error(),
		}).Error("Failed to fetch articles for author")
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
		}, "layouts/admin")
	}

	email := strings.TrimSpace(c.FormValue("email"))

	if email == "" {
		return c.Render("admin/invite", fiber.Map{
			"Title":      "Send Invitation",
			"Error":      "Email address is required",
			"csrf_token": c.Locals("csrf_token"),
		}, "layouts/admin")
	}

	// Validate email format
	if !isValidEmail(email) {
		return c.Render("admin/invite", fiber.Map{
			"Title":      "Send Invitation",
			"Error":      "Please enter a valid email address",
			"csrf_token": c.Locals("csrf_token"),
			"Email":      email,
		}, "layouts/admin")
	}

	invitation, err := a.CreateInvitation(user.ID, email)
	if err != nil {
		return c.Render("admin/invite", fiber.Map{
			"Title":      "Send Invitation",
			"Error":      err.Error(),
			"csrf_token": c.Locals("csrf_token"),
		}, "layouts/admin")
	}

	err = a.EmailService.SendInvitation(email, invitation.Token)
	if err != nil {
		return c.Render("admin/invite", fiber.Map{
			"Title":      "Send Invitation",
			"Error":      "Failed to send invitation email",
			"csrf_token": c.Locals("csrf_token"),
		}, "layouts/admin")
	}

	return c.Render("admin/invite", fiber.Map{
		"Title":      "Send Invitation",
		"Success":    "Invitation sent successfully to " + email,
		"csrf_token": c.Locals("csrf_token"),
	}, "layouts/admin")
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
	email := strings.TrimSpace(c.FormValue("email"))
	password := c.FormValue("password")
	fullName := strings.TrimSpace(c.FormValue("full_name"))

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

	// Validate email format
	if !isValidEmail(email) {
		return c.Render("auth/register", fiber.Map{
			"Title":      "Complete Registration",
			"Token":      token,
			"Email":      email,
			"FullName":   fullName,
			"Error":      "Please enter a valid email address",
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
		"Title":      "Invite Users",
		"InvitePage": true,
		"csrf_token": c.Locals("csrf_token"),
	}), "layouts/admin")
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
	
	fullName := strings.TrimSpace(c.FormValue("full_name"))
	email := strings.TrimSpace(c.FormValue("email"))
	
	if fullName == "" || email == "" {
		return c.Render("pages/profile", a.GetTemplateData(c, fiber.Map{
			"Title":        "Profile",
			"ArticleCount": articleCount,
			"Error":        "Full name and email are required",
		}), "layouts/base")
	}

	// Validate email format
	if !isValidEmail(email) {
		return c.Render("pages/profile", a.GetTemplateData(c, fiber.Map{
			"Title":        "Profile",
			"ArticleCount": articleCount,
			"Error":        "Please enter a valid email address",
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
	email := strings.TrimSpace(c.FormValue("email"))

	if email == "" {
		return c.Render("auth/forgot-password", fiber.Map{
			"Title":      "Forgot Password",
			"csrf_token": c.Locals("csrf_token"),
			"Error":      "Email address is required",
		}, "layouts/base")
	}

	// Validate email format
	if !isValidEmail(email) {
		return c.Render("auth/forgot-password", fiber.Map{
			"Title":      "Forgot Password",
			"csrf_token": c.Locals("csrf_token"),
			"Error":      "Please enter a valid email address",
			"Email":      email,
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

// Article Management Handlers

// Show article management list
func (a *App) ArticleManagementHandler(c *fiber.Ctx) error {
	articles, err := a.GetAllArticlesForManagement()
	if err != nil {
		log.Printf("Failed to get articles for management: %v", err)
		return fiber.ErrInternalServerError
	}
	
	templateData := fiber.Map{
		"Title":        "Articles",
		"ArticlesPage": true,
		"Articles":     articles,
	}
	
	// Handle success/error messages from query params
	if success := c.Query("success"); success != "" {
		templateData["Success"] = success
	}
	if errorMsg := c.Query("error"); errorMsg != "" {
		templateData["Error"] = errorMsg
	}
	
	return c.Render("admin/articles", a.GetTemplateData(c, templateData), "layouts/admin")
}

// Show new article form
func (a *App) NewArticleHandler(c *fiber.Ctx) error {
	return c.Render("admin/article-form", a.GetTemplateData(c, fiber.Map{
		"Title":          "New Article",
		"NewArticlePage": true,
		"Article":        Article{}, // Empty article for new form
	}), "layouts/admin")
}

// Show edit article form
func (a *App) EditArticleHandler(c *fiber.Ctx) error {
	id := c.Params("id")
	article, err := a.GetArticleByID(id)
	if err != nil {
		log.Printf("Article not found: %v", err)
		return fiber.ErrNotFound
	}
	
	return c.Render("admin/article-form", a.GetTemplateData(c, fiber.Map{
		"Title":   "Edit Article",
		"Article": article,
	}), "layouts/admin")
}

// Create new article
func (a *App) CreateArticleHandler(c *fiber.Ctx) error {
	user, err := a.GetCurrentUser(c)
	if err != nil {
		return c.Redirect("/login")
	}
	
	title := strings.TrimSpace(c.FormValue("title"))
	slug := strings.TrimSpace(c.FormValue("slug"))
	body := strings.TrimSpace(c.FormValue("body"))
	publishStatus := c.FormValue("publish_status")
	
	// Validate required fields
	if title == "" || slug == "" || body == "" {
		return c.Render("admin/article-form", a.GetTemplateData(c, fiber.Map{
			"Title":          "New Article",
			"NewArticlePage": true,
			"Article": Article{
				Title: title,
				Slug:  slug,
				Body:  body,
			},
			"Error": "Title, slug, and content are required",
		}), "layouts/admin")
	}
	
	// Validate slug format
	if !isValidSlug(slug) {
		return c.Render("admin/article-form", a.GetTemplateData(c, fiber.Map{
			"Title": "New Article",
			"Article": Article{
				Title: title,
				Slug:  slug,
				Body:  body,
			},
			"Error": "Slug must contain only lowercase letters, numbers, and hyphens",
		}), "layouts/base")
	}
	
	publish := publishStatus == "publish"
	
	article, err := a.CreateArticle(title, slug, body, user.ID, publish)
	if err != nil {
		log.Printf("Failed to create article: %v", err)
		errorMsg := "Failed to create article"
		if strings.Contains(err.Error(), "slug already exists") {
			errorMsg = "A article with this slug already exists. Please choose a different slug."
		}
		
		return c.Render("admin/article-form", a.GetTemplateData(c, fiber.Map{
			"Title": "New Article",
			"Article": Article{
				Title: title,
				Slug:  slug,
				Body:  body,
			},
			"Error": errorMsg,
		}), "layouts/base")
	}
	
	status := "draft"
	if publish {
		status = "published"
	}
	
	log.Printf("Article created by %s: %s (%s)", user.EmailAddress, article.Title, status)
	return c.Redirect("/admin/articles?success=" + "Article created successfully!")
}

// Update existing article
func (a *App) UpdateArticleHandler(c *fiber.Ctx) error {
	id := c.Params("id")
	articleID, err := strconv.ParseUint(id, 10, 32)
	if err != nil {
		return fiber.ErrBadRequest
	}
	
	title := strings.TrimSpace(c.FormValue("title"))
	slug := strings.TrimSpace(c.FormValue("slug"))
	body := strings.TrimSpace(c.FormValue("body"))
	publishStatus := c.FormValue("publish_status")
	
	// Get original article for form repopulation on error
	originalArticle, err := a.GetArticleByID(id)
	if err != nil {
		return fiber.ErrNotFound
	}
	
	// Validate required fields
	if title == "" || slug == "" || body == "" {
		return c.Render("admin/article-form", a.GetTemplateData(c, fiber.Map{
			"Title": "Edit Article",
			"Article": &Article{
				Model:   originalArticle.Model,
				Title:   title,
				Slug:    slug,
				Body:    body,
				AuthorID: originalArticle.AuthorID,
				Author:   originalArticle.Author,
				PublishedAt: originalArticle.PublishedAt,
			},
			"Error": "Title, slug, and content are required",
		}), "layouts/base")
	}
	
	// Validate slug format
	if !isValidSlug(slug) {
		return c.Render("admin/article-form", a.GetTemplateData(c, fiber.Map{
			"Title": "Edit Article",
			"Article": &Article{
				Model:   originalArticle.Model,
				Title:   title,
				Slug:    slug,
				Body:    body,
				AuthorID: originalArticle.AuthorID,
				Author:   originalArticle.Author,
				PublishedAt: originalArticle.PublishedAt,
			},
			"Error": "Slug must contain only lowercase letters, numbers, and hyphens",
		}), "layouts/base")
	}
	
	publish := publishStatus == "publish"
	
	article, err := a.UpdateArticle(uint(articleID), title, slug, body, publish)
	if err != nil {
		log.Printf("Failed to update article: %v", err)
		errorMsg := "Failed to update article"
		if strings.Contains(err.Error(), "slug already exists") {
			errorMsg = "A article with this slug already exists. Please choose a different slug."
		}
		
		return c.Render("admin/article-form", a.GetTemplateData(c, fiber.Map{
			"Title": "Edit Article",
			"Article": &Article{
				Model:   originalArticle.Model,
				Title:   title,
				Slug:    slug,
				Body:    body,
				AuthorID: originalArticle.AuthorID,
				Author:   originalArticle.Author,
				PublishedAt: originalArticle.PublishedAt,
			},
			"Error": errorMsg,
		}), "layouts/base")
	}
	
	log.Printf("Article updated: %s", article.Title)
	return c.Redirect("/admin/articles?success=" + "Article updated successfully!")
}

// Publish article
func (a *App) PublishArticleHandler(c *fiber.Ctx) error {
	id := c.Params("id")
	articleID, err := strconv.ParseUint(id, 10, 32)
	if err != nil {
		return fiber.ErrBadRequest
	}
	
	err = a.PublishArticle(uint(articleID))
	if err != nil {
		log.Printf("Failed to publish article: %v", err)
		return c.Redirect("/admin/articles?error=" + "Failed to publish article")
	}
	
	log.Printf("Article published: ID %d", articleID)
	return c.Redirect("/admin/articles?success=" + "Article published successfully!")
}

// Unpublish article
func (a *App) UnpublishArticleHandler(c *fiber.Ctx) error {
	id := c.Params("id")
	articleID, err := strconv.ParseUint(id, 10, 32)
	if err != nil {
		return fiber.ErrBadRequest
	}
	
	err = a.UnpublishArticle(uint(articleID))
	if err != nil {
		log.Printf("Failed to unpublish article: %v", err)
		return c.Redirect("/admin/articles?error=" + "Failed to unpublish article")
	}
	
	log.Printf("Article unpublished: ID %d", articleID)
	return c.Redirect("/admin/articles?success=" + "Article unpublished successfully!")
}

// Delete article
func (a *App) DeleteArticleHandler(c *fiber.Ctx) error {
	id := c.Params("id")
	articleID, err := strconv.ParseUint(id, 10, 32)
	if err != nil {
		return fiber.ErrBadRequest
	}
	
	err = a.DeleteArticle(uint(articleID))
	if err != nil {
		log.Printf("Failed to delete article: %v", err)
		return c.Redirect("/admin/articles?error=" + "Failed to delete article")
	}
	
	log.Printf("Article deleted: ID %d", articleID)
	return c.Redirect("/admin/articles?success=" + "Article deleted successfully!")
}

// Image upload handler for Markdown editor
func (a *App) UploadImageHandler(c *fiber.Ctx) error {
	// Check if user is authenticated and admin
	user, err := a.GetCurrentUser(c)
	if err != nil {
		return c.Status(401).JSON(fiber.Map{
			"error": "Authentication required",
		})
	}

	if !user.IsAdmin {
		return c.Status(403).JSON(fiber.Map{
			"error": "Admin access required",
		})
	}

	// Parse multipart form
	file, err := c.FormFile("image")
	if err != nil {
		LogHTTP().WithError(err).Error("Failed to parse uploaded file")
		return c.Status(400).JSON(fiber.Map{
			"error": "No image file provided",
		})
	}

	// Validate file type
	if !isValidImageType(file.Header.Get("Content-Type")) {
		return c.Status(400).JSON(fiber.Map{
			"error": "Invalid file type. Only JPEG, PNG, GIF, and WebP images are allowed",
		})
	}

	// Validate file size (max 5MB)
	maxSize := int64(5 * 1024 * 1024) // 5MB
	if file.Size > maxSize {
		return c.Status(400).JSON(fiber.Map{
			"error": "File too large. Maximum size is 5MB",
		})
	}

	// Generate unique filename
	ext := filepath.Ext(file.Filename)
	filename := fmt.Sprintf("%d%s", time.Now().UnixNano(), ext)

	// Create upload directory if it doesn't exist
	uploadDir := filepath.Join("static", "uploads")
	if err := os.MkdirAll(uploadDir, 0755); err != nil {
		LogHTTP().WithError(err).Error("Failed to create upload directory")
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to create upload directory",
		})
	}

	// Save file
	filepath := filepath.Join(uploadDir, filename)
	if err := saveUploadedFile(file, filepath); err != nil {
		LogHTTP().WithError(err).Error("Failed to save uploaded file")
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to save image",
		})
	}

	// Return success response with image URL
	imageURL := fmt.Sprintf("/static/uploads/%s", filename)

	LogHTTP().WithFields(map[string]interface{}{
		"user": SanitizeEmail(user.EmailAddress),
		"filename": filename,
		"size": file.Size,
	}).Info("Image uploaded successfully")

	return c.JSON(fiber.Map{
		"success": true,
		"url":     imageURL,
		"filename": filename,
	})
}

// Helper function to validate image MIME types
func isValidImageType(contentType string) bool {
	validTypes := []string{
		"image/jpeg",
		"image/jpg",
		"image/png",
		"image/gif",
		"image/webp",
	}

	for _, validType := range validTypes {
		if contentType == validType {
			return true
		}
	}
	return false
}

// Helper function to save uploaded file
func saveUploadedFile(file *multipart.FileHeader, dst string) error {
	src, err := file.Open()
	if err != nil {
		return err
	}
	defer src.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, src)
	return err
}

// PAGE HANDLERS

// Display page by slug
func (a *App) PageHandler(c *fiber.Ctx) error {
	slug := c.Params("slug")
	page, err := a.GetPage(slug)
	if err != nil {
		LogHTTP().WithFields(map[string]interface{}{
			"slug": slug,
			"error": err.Error(),
		}).Warn("Page not found")
		return fiber.ErrNotFound
	}

	// Convert markdown body to HTML
	renderedBody, err := MarkdownToHTML(page.Body)
	if err != nil {
		LogHTTP().WithFields(map[string]interface{}{
			"slug": slug,
			"error": err.Error(),
		}).Error("Failed to render markdown")
		// Fallback to raw body if markdown rendering fails
		renderedBody = template.HTML(page.Body)
	}

	// Create a template-friendly version with rendered HTML
	templatePage := struct {
		*Page
		RenderedBody template.HTML
	}{
		Page:         page,
		RenderedBody: renderedBody,
	}

	return c.Render("page", a.GetTemplateData(c, fiber.Map{
		"Title":   page.Title,
		"Message": "Page",
		"Page":    templatePage,
	}), "layouts/base")
}

// Show pages management list
func (a *App) PageManagementHandler(c *fiber.Ctx) error {
	pages, err := a.GetAllPages()
	if err != nil {
		LogHTTP().WithError(err).Error("Failed to fetch pages")
		return fiber.ErrInternalServerError
	}

	return c.Render("admin/pages", a.GetTemplateData(c, fiber.Map{
		"Title":     "Page Management",
		"PagesPage": true,
		"Pages":     pages,
		"Success":   c.Query("success"),
		"Error":     c.Query("error"),
	}), "layouts/admin")
}

// Show new page form
func (a *App) NewPageHandler(c *fiber.Ctx) error {
	return c.Render("admin/page-form", a.GetTemplateData(c, fiber.Map{
		"Title":       "New Page",
		"NewPagePage": true,
		"Page":        Page{}, // Empty page for new form
	}), "layouts/admin")
}

// Create new page
func (a *App) CreatePageHandler(c *fiber.Ctx) error {
	user, err := a.GetCurrentUser(c)
	if err != nil {
		return c.Redirect("/login")
	}

	title := strings.TrimSpace(c.FormValue("title"))
	slug := strings.TrimSpace(c.FormValue("slug"))
	body := strings.TrimSpace(c.FormValue("body"))

	// Validate required fields
	if title == "" || slug == "" || body == "" {
		return c.Render("admin/page-form", a.GetTemplateData(c, fiber.Map{
			"Title":       "New Page",
			"NewPagePage": true,
			"Page": Page{
				Title: title,
				Slug:  slug,
				Body:  body,
			},
			"Error": "All fields are required",
		}), "layouts/admin")
	}

	// Additional validation
	if !isValidPageSlug(slug) {
		return c.Render("admin/page-form", a.GetTemplateData(c, fiber.Map{
			"Title":       "New Page",
			"NewPagePage": true,
			"Page": Page{
				Title: title,
				Slug:  slug,
				Body:  body,
			},
			"Error": "Invalid slug. Use only lowercase letters, numbers, and hyphens. Slug cannot conflict with existing routes.",
		}), "layouts/admin")
	}

	// Create the page
	page, err := a.CreatePage(title, slug, body, user.ID)
	if err != nil {
		LogHTTP().WithFields(map[string]interface{}{
			"user":  SanitizeEmail(user.EmailAddress),
			"title": title,
			"slug":  slug,
			"error": err.Error(),
		}).Error("Failed to create page")

		return c.Render("admin/page-form", a.GetTemplateData(c, fiber.Map{
			"Title":       "New Page",
			"NewPagePage": true,
			"Page": Page{
				Title: title,
				Slug:  slug,
				Body:  body,
			},
			"Error": err.Error(),
		}), "layouts/admin")
	}

	LogHTTP().WithFields(map[string]interface{}{
		"user":    SanitizeEmail(user.EmailAddress),
		"page_id": page.ID,
		"title":   page.Title,
		"slug":    page.Slug,
	}).Info("Page created successfully")

	return c.Redirect("/admin/pages?success=Page created successfully!")
}

// Show edit page form
func (a *App) EditPageHandler(c *fiber.Ctx) error {
	id := c.Params("id")
	page, err := a.GetPageByID(id)
	if err != nil {
		log.Printf("Page not found: %v", err)
		return fiber.ErrNotFound
	}

	return c.Render("admin/page-form", a.GetTemplateData(c, fiber.Map{
		"Title":     "Edit Page",
		"PagesPage": true,
		"Page":      page,
	}), "layouts/admin")
}

// Update existing page
func (a *App) UpdatePageHandler(c *fiber.Ctx) error {
	id := c.Params("id")
	pageID, err := strconv.ParseUint(id, 10, 32)
	if err != nil {
		return fiber.ErrBadRequest
	}

	title := strings.TrimSpace(c.FormValue("title"))
	slug := strings.TrimSpace(c.FormValue("slug"))
	body := strings.TrimSpace(c.FormValue("body"))

	// Get original page for form repopulation on error
	originalPage, err := a.GetPageByID(id)
	if err != nil {
		return fiber.ErrNotFound
	}

	// Validate required fields
	if title == "" || slug == "" || body == "" {
		return c.Render("admin/page-form", a.GetTemplateData(c, fiber.Map{
			"Title": "Edit Page",
			"Page": Page{
				Model: originalPage.Model,
				Title: title,
				Slug:  slug,
				Body:  body,
			},
			"Error": "All fields are required",
		}), "layouts/admin")
	}

	// Additional validation
	if !isValidPageSlug(slug) {
		return c.Render("admin/page-form", a.GetTemplateData(c, fiber.Map{
			"Title": "Edit Page",
			"Page": Page{
				Model: originalPage.Model,
				Title: title,
				Slug:  slug,
				Body:  body,
			},
			"Error": "Invalid slug. Use only lowercase letters, numbers, and hyphens. Slug cannot conflict with existing routes.",
		}), "layouts/admin")
	}

	// Update the page
	err = a.UpdatePage(uint(pageID), title, slug, body)
	if err != nil {
		LogHTTP().WithFields(map[string]interface{}{
			"page_id": pageID,
			"error":   err.Error(),
		}).Error("Failed to update page")

		return c.Render("admin/page-form", a.GetTemplateData(c, fiber.Map{
			"Title": "Edit Page",
			"Page": Page{
				Model: originalPage.Model,
				Title: title,
				Slug:  slug,
				Body:  body,
			},
			"Error": err.Error(),
		}), "layouts/admin")
	}

	LogHTTP().WithFields(map[string]interface{}{
		"page_id": pageID,
		"title":   title,
		"slug":    slug,
	}).Info("Page updated successfully")

	return c.Redirect("/admin/pages?success=Page updated successfully!")
}

// Activate page
func (a *App) ActivatePageHandler(c *fiber.Ctx) error {
	id := c.Params("id")
	pageID, err := strconv.ParseUint(id, 10, 32)
	if err != nil {
		return fiber.ErrBadRequest
	}

	err = a.ActivatePage(uint(pageID))
	if err != nil {
		log.Printf("Failed to activate page: %v", err)
		return c.Redirect("/admin/pages?error=" + "Failed to activate page")
	}

	log.Printf("Page activated: ID %d", pageID)
	return c.Redirect("/admin/pages?success=" + "Page activated successfully!")
}

// Deactivate page
func (a *App) DeactivatePageHandler(c *fiber.Ctx) error {
	id := c.Params("id")
	pageID, err := strconv.ParseUint(id, 10, 32)
	if err != nil {
		return fiber.ErrBadRequest
	}

	err = a.DeactivatePage(uint(pageID))
	if err != nil {
		log.Printf("Failed to deactivate page: %v", err)
		return c.Redirect("/admin/pages?error=" + "Failed to deactivate page")
	}

	log.Printf("Page deactivated: ID %d", pageID)
	return c.Redirect("/admin/pages?success=" + "Page deactivated successfully!")
}

// Delete page
func (a *App) DeletePageHandler(c *fiber.Ctx) error {
	id := c.Params("id")
	pageID, err := strconv.ParseUint(id, 10, 32)
	if err != nil {
		return fiber.ErrBadRequest
	}

	err = a.DeletePage(uint(pageID))
	if err != nil {
		log.Printf("Failed to delete page: %v", err)
		return c.Redirect("/admin/pages?error=" + "Failed to delete page")
	}

	log.Printf("Page deleted: ID %d", pageID)
	return c.Redirect("/admin/pages?success=" + "Page deleted successfully!")
}

// isValidSlug is now in validation.go

// NAVIGATION HANDLERS

// Show navigation management list
func (a *App) NavigationManagementHandler(c *fiber.Ctx) error {
	items, err := a.GetAllNavigationItems()
	if err != nil {
		LogHTTP().WithError(err).Error("Failed to fetch navigation items")
		return fiber.ErrInternalServerError
	}

	return c.Render("admin/navigation", a.GetTemplateData(c, fiber.Map{
		"Title":          "Navigation Management",
		"NavigationPage": true,
		"Items":          items,
		"Success":        c.Query("success"),
		"Error":          c.Query("error"),
	}), "layouts/admin")
}

// Show new navigation item form
func (a *App) NewNavigationHandler(c *fiber.Ctx) error {
	return c.Render("admin/navigation-form", a.GetTemplateData(c, fiber.Map{
		"Title":             "New Navigation Item",
		"NewNavigationPage": true,
		"Item":              NavigationItem{Target: "_self"}, // Default values
	}), "layouts/admin")
}

// Create new navigation item
func (a *App) CreateNavigationHandler(c *fiber.Ctx) error {
	user, err := a.GetCurrentUser(c)
	if err != nil {
		return c.Redirect("/login")
	}

	title := strings.TrimSpace(c.FormValue("title"))
	url := strings.TrimSpace(c.FormValue("url"))
	target := strings.TrimSpace(c.FormValue("target"))
	orderStr := strings.TrimSpace(c.FormValue("order"))

	// Parse order
	order := 0
	if orderStr != "" {
		if parsedOrder, parseErr := strconv.Atoi(orderStr); parseErr == nil {
			order = parsedOrder
		}
	}

	// Validate required fields
	if title == "" || url == "" {
		return c.Render("admin/navigation-form", a.GetTemplateData(c, fiber.Map{
			"Title":             "New Navigation Item",
			"NewNavigationPage": true,
			"Item": NavigationItem{
				Title:  title,
				URL:    url,
				Target: target,
				Order:  order,
			},
			"Error": "Title and URL are required",
		}), "layouts/admin")
	}

	// Create the navigation item
	item, err := a.CreateNavigationItem(title, url, order, target)
	if err != nil {
		LogHTTP().WithFields(map[string]interface{}{
			"user":  SanitizeEmail(user.EmailAddress),
			"title": title,
			"url":   url,
			"error": err.Error(),
		}).Error("Failed to create navigation item")

		return c.Render("admin/navigation-form", a.GetTemplateData(c, fiber.Map{
			"Title":             "New Navigation Item",
			"NewNavigationPage": true,
			"Item": NavigationItem{
				Title:  title,
				URL:    url,
				Target: target,
				Order:  order,
			},
			"Error": err.Error(),
		}), "layouts/admin")
	}

	LogHTTP().WithFields(map[string]interface{}{
		"user":    SanitizeEmail(user.EmailAddress),
		"item_id": item.ID,
		"title":   item.Title,
		"url":     item.URL,
	}).Info("Navigation item created successfully")

	return c.Redirect("/admin/navigation?success=Navigation item created successfully!")
}

// Show edit navigation item form
func (a *App) EditNavigationHandler(c *fiber.Ctx) error {
	id := c.Params("id")
	item, err := a.GetNavigationItemByID(id)
	if err != nil {
		LogHTTP().WithFields(map[string]interface{}{
			"id":    id,
			"error": err.Error(),
		}).Error("Navigation item not found")
		return fiber.ErrNotFound
	}

	return c.Render("admin/navigation-form", a.GetTemplateData(c, fiber.Map{
		"Title":          "Edit Navigation Item",
		"NavigationPage": true,
		"Item":           item,
	}), "layouts/admin")
}

// Update existing navigation item
func (a *App) UpdateNavigationHandler(c *fiber.Ctx) error {
	id := c.Params("id")
	itemID, err := strconv.ParseUint(id, 10, 32)
	if err != nil {
		return fiber.ErrBadRequest
	}

	title := strings.TrimSpace(c.FormValue("title"))
	url := strings.TrimSpace(c.FormValue("url"))
	target := strings.TrimSpace(c.FormValue("target"))
	active := c.FormValue("active") == "on"
	orderStr := strings.TrimSpace(c.FormValue("order"))

	// Parse order
	order := 0
	if orderStr != "" {
		if parsedOrder, parseErr := strconv.Atoi(orderStr); parseErr == nil {
			order = parsedOrder
		}
	}

	// Get original item for form repopulation on error
	originalItem, err := a.GetNavigationItemByID(id)
	if err != nil {
		return fiber.ErrNotFound
	}

	// Validate required fields
	if title == "" || url == "" {
		return c.Render("admin/navigation-form", a.GetTemplateData(c, fiber.Map{
			"Title": "Edit Navigation Item",
			"Item": NavigationItem{
				Model:  originalItem.Model,
				Title:  title,
				URL:    url,
				Target: target,
				Order:  order,
				Active: active,
			},
			"Error": "Title and URL are required",
		}), "layouts/admin")
	}

	// Update the navigation item
	err = a.UpdateNavigationItem(uint(itemID), title, url, order, target, active)
	if err != nil {
		LogHTTP().WithFields(map[string]interface{}{
			"item_id": itemID,
			"error":   err.Error(),
		}).Error("Failed to update navigation item")

		return c.Render("admin/navigation-form", a.GetTemplateData(c, fiber.Map{
			"Title": "Edit Navigation Item",
			"Item": NavigationItem{
				Model:  originalItem.Model,
				Title:  title,
				URL:    url,
				Target: target,
				Order:  order,
				Active: active,
			},
			"Error": err.Error(),
		}), "layouts/admin")
	}

	LogHTTP().WithFields(map[string]interface{}{
		"item_id": itemID,
		"title":   title,
		"url":     url,
	}).Info("Navigation item updated successfully")

	return c.Redirect("/admin/navigation?success=Navigation item updated successfully!")
}

// Toggle navigation item active status
func (a *App) ToggleNavigationHandler(c *fiber.Ctx) error {
	id := c.Params("id")
	itemID, err := strconv.ParseUint(id, 10, 32)
	if err != nil {
		return fiber.ErrBadRequest
	}

	err = a.ToggleNavigationItem(uint(itemID))
	if err != nil {
		LogHTTP().WithFields(map[string]interface{}{
			"item_id": itemID,
			"error":   err.Error(),
		}).Error("Failed to toggle navigation item")
		return c.Redirect("/admin/navigation?error=" + "Failed to toggle navigation item")
	}

	LogHTTP().WithField("item_id", itemID).Info("Navigation item toggled")
	return c.Redirect("/admin/navigation?success=" + "Navigation item updated successfully!")
}

// Delete navigation item
func (a *App) DeleteNavigationHandler(c *fiber.Ctx) error {
	id := c.Params("id")
	itemID, err := strconv.ParseUint(id, 10, 32)
	if err != nil {
		return fiber.ErrBadRequest
	}

	err = a.DeleteNavigationItem(uint(itemID))
	if err != nil {
		LogHTTP().WithFields(map[string]interface{}{
			"item_id": itemID,
			"error":   err.Error(),
		}).Error("Failed to delete navigation item")
		return c.Redirect("/admin/navigation?error=" + "Failed to delete navigation item")
	}

	LogHTTP().WithField("item_id", itemID).Info("Navigation item deleted")
	return c.Redirect("/admin/navigation?success=" + "Navigation item deleted successfully!")
}
