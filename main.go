package main

import (
	"embed"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/template/django/v3"
	"log"
	"net/http"
)

//go:embed all:static
var staticAssets embed.FS

//go:embed templates
var templateAssets embed.FS

func main() {
	log.Println("Welcome to the blog app.")
	engine := django.NewPathForwardingFileSystem(http.FS(templateAssets), "/templates", ".html")
	//engine := django.New("./templates", ".html")
	mux := fiber.New(fiber.Config{
		Views: engine,
	})
	mux.Static("/static", "static")

	mux.Get("/", IndexHandler)
	mux.Get("/article/:slug", ArticleHandler)
	mux.Get("/about", AboutHandler)

	log.Fatal(mux.Listen(":3000"))
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
