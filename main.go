package main

import (
	"embed"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
	"github.com/gofiber/template/django/v3"
	"gorm.io/gorm"
	"log"
	"net/http"
)

//go:embed all:static
var staticAssets embed.FS

//go:embed templates
var templateAssets embed.FS

type App struct {
	Config       Config
	DB           *gorm.DB
	Router       *fiber.App
	EmailService EmailService
	SessionStore *session.Store
}

func main() {
	app := App{}
	app.Config = LoadConfig()

	// Initialize structured logging
	InitLogger(app.Config)
	AppLogger.Info("Starting blog application...")

	app.DB = SetupDatabase(app.Config)
	app.SetupEmailService()
	app.SetupSessions()
	app.SeedDatabase()
	app.SetupTemplatesAndStaticFiles()
	app.DefineRoutes()

	AppLogger.WithField("port", 3000).Info("Blog application ready to serve requests")
	log.Fatal(app.Router.Listen(":3000"))
}

func (a *App) SetupTemplatesAndStaticFiles() {
	engine := django.NewPathForwardingFileSystem(http.FS(templateAssets), "/templates", ".html")
	a.Router = fiber.New(fiber.Config{
		Views: engine,
	})
	a.Router.Static("/static", "static")
}

func (a *App) DefineRoutes() {
	a.Router.Use(a.CSRFMiddleware())
	a.Router.Use(a.InjectUserMiddleware)

	a.Router.Get("/", a.IndexHandler)
	a.Router.Get("/article/:slug", a.ArticleHandler)
	a.Router.Get("/author/:id", a.AuthorHandler)

	// Authentication routes (with rate limiting)
	a.Router.Get("/login", a.LoginHandler)
	a.Router.Post("/login", a.AuthRateLimiter(), a.LoginPostHandler)
	a.Router.Post("/verify", a.AuthRateLimiter(), a.VerifyCodeHandler)
	a.Router.Get("/logout", a.LogoutHandler)

	// Password reset routes (with stricter rate limiting)
	a.Router.Get("/forgot-password", a.ForgotPasswordHandler)
	a.Router.Post("/forgot-password", a.PasswordResetRateLimiter(), a.ForgotPasswordPostHandler)
	a.Router.Get("/reset-password", a.ResetPasswordHandler)
	a.Router.Post("/reset-password", a.AuthRateLimiter(), a.ResetPasswordPostHandler)

	a.Router.Get("/register", a.RegisterHandler)
	a.Router.Post("/register", a.AuthRateLimiter(), a.ProcessRegistrationHandler)

	// Protected Routes (Public-facing)
	a.Router.Get("/dashboard", a.RequireAuth, a.DashboardHandler)
	a.Router.Get("/user/profile", a.RequireAuth, a.ProfileHandler)
	a.Router.Get("/profile", a.RequireAuth, a.ProfileHandler) // Alternative shorter route
	a.Router.Post("/profile/update", a.RequireAuth, a.UpdateProfileHandler)
	a.Router.Post("/profile/change-password", a.RequireAuth, a.ChangePasswordHandler)
	
	// Admin Routes - WordPress-style admin panel
	a.Router.Get("/admin", a.RequireAuth, a.RequireAdmin, a.AdminDashboardHandler)
	a.Router.Get("/admin/", a.RequireAuth, a.RequireAdmin, a.AdminDashboardHandler) // Alternative
	
	// Admin - Article management
	a.Router.Get("/admin/articles", a.RequireAuth, a.RequireAdmin, a.ArticleManagementHandler)
	a.Router.Get("/admin/articles/new", a.RequireAuth, a.RequireAdmin, a.NewArticleHandler)
	a.Router.Post("/admin/articles/create", a.RequireAuth, a.RequireAdmin, a.CreateArticleHandler)
	a.Router.Get("/admin/articles/:id/edit", a.RequireAuth, a.RequireAdmin, a.EditArticleHandler)
	a.Router.Post("/admin/articles/:id/update", a.RequireAuth, a.RequireAdmin, a.UpdateArticleHandler)
	a.Router.Post("/admin/articles/:id/publish", a.RequireAuth, a.RequireAdmin, a.PublishArticleHandler)
	a.Router.Post("/admin/articles/:id/unpublish", a.RequireAuth, a.RequireAdmin, a.UnpublishArticleHandler)
	a.Router.Post("/admin/articles/:id/delete", a.RequireAuth, a.RequireAdmin, a.DeleteArticleHandler)
	
	// Admin - Page management
	a.Router.Get("/admin/pages", a.RequireAuth, a.RequireAdmin, a.PageManagementHandler)
	a.Router.Get("/admin/pages/new", a.RequireAuth, a.RequireAdmin, a.NewPageHandler)
	a.Router.Post("/admin/pages/create", a.RequireAuth, a.RequireAdmin, a.CreatePageHandler)
	a.Router.Get("/admin/pages/:id/edit", a.RequireAuth, a.RequireAdmin, a.EditPageHandler)
	a.Router.Post("/admin/pages/:id/update", a.RequireAuth, a.RequireAdmin, a.UpdatePageHandler)
	a.Router.Post("/admin/pages/:id/activate", a.RequireAuth, a.RequireAdmin, a.ActivatePageHandler)
	a.Router.Post("/admin/pages/:id/deactivate", a.RequireAuth, a.RequireAdmin, a.DeactivatePageHandler)
	a.Router.Post("/admin/pages/:id/delete", a.RequireAuth, a.RequireAdmin, a.DeletePageHandler)

	// Admin - User management
	a.Router.Get("/admin/invite", a.RequireAuth, a.RequireAdmin, a.InviteFormHandler)
	a.Router.Post("/admin/invite", a.RequireAuth, a.RequireAdmin, a.SendInviteHandler)

	// Image upload for Markdown editor
	a.Router.Post("/admin/upload-image", a.RequireAuth, a.RequireAdmin, a.UploadImageHandler)

	// Dynamic page routes (must be last to avoid conflicts)
	a.Router.Get("/:slug", a.PageHandler)
}
