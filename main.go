package main

import (
	"embed"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/template/django/v3"
	"log"
	"net/http"

	"github.com/mickgardner/blog/internal/config"
	"github.com/mickgardner/blog/internal/database"
	"gorm.io/gorm"
)

//go:embed all:static
var staticAssets embed.FS

//go:embed templates
var templateAssets embed.FS

type App struct {
	Config config.Config
	DB     *gorm.DB
	Router *fiber.App
}

func main() {
	log.Println("Welcome to the blog app.")
	app := App{}
	app.DB = database.SetupDatabase(app.Config)
	app.SetupTemplatesAndStaticFiles()
	app.DefineRoutes()

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
	a.Router.Get("/", IndexHandler)
	a.Router.Get("/article/:slug", ArticleHandler)
	a.Router.Get("/about", AboutHandler)
}

func IndexHandler(c *fiber.Ctx) error {
	log.Println("IndexHandler")
	return c.Render("index", fiber.Map{
		"Title":   "Blog Homepage",
		"Message": "Hello Blog",
	}, "layouts/base")
}

func ArticleHandler(c *fiber.Ctx) error {
	log.Println("ArticleHandler")
	return c.Render("article", fiber.Map{
		"Title":   "<blog keywords and title>",
		"Message": "Blog Article",
	}, "layouts/base")
}

func AboutHandler(c *fiber.Ctx) error {
	log.Println("AboutHandler")
	return c.Render("pages/about", fiber.Map{
		"Title":   "About Page",
		"Message": "About Page",
	}, "layouts/base")
}
