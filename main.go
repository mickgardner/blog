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
	log.Println("Starting blog application...")
	app := App{}
	app.Config = LoadConfig()
	app.DB = SetupDatabase(app.Config)
	app.SetupEmailService()
	app.SetupSessions()
	app.SeedDatabase()
	app.SetupTemplatesAndStaticFiles()
	app.DefineRoutes()
	log.Println("Welcome to the blog app.")

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
	a.Router.Get("/about", a.AboutHandler)

	// Authentication routes
	a.Router.Get("/login", a.LoginHandler)
	a.Router.Post("/login", a.RequestCodeHandler)
	a.Router.Post("/verify", a.VerifyCodeHandler)
	a.Router.Get("/logout", a.LogoutHandler)

	// Protected Routes
	a.Router.Get("/dashboard", a.RequireAuth, a.DashboardHandler)
	a.Router.Get("/user/profile", a.RequireAuth, a.ProfileHandler)
}
