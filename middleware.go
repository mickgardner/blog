package main

import (
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/csrf"
)

// Middleware to inject current user into all template contexts.
func (a *App) InjectUserMiddleware(c *fiber.Ctx) error {
	// Get current user (nil if not logged in)
	user, _ := a.GetCurrentUser(c)

	// Store user in fiber context for templates.
	c.Locals("User", user)
	c.Locals("IsAuthenticated", user != nil)

	return c.Next()
}

// Authentication Middleware - protects routes that require login
func (a *App) RequireAuth(c *fiber.Ctx) error {
	if !a.IsAuthenticated(c) {
		// User not authenticated.
		// Store the original URL they wanted to visit.
		sess, _ := a.SessionStore.Get(c)
		sess.Set("redirect_after_login", c.OriginalURL())
		sess.Save()

		return c.Redirect("/login")
	}

	return c.Next() // Continue to protected route
}

// Redirect Middleware after login
func (a *App) RedirectAfterLogin(c *fiber.Ctx) string {
	sess, err := a.SessionStore.Get(c)
	if err != nil {
		return "/"
	}

	redirectURL := sess.Get("redirect_after_login")
	if redirectURL != nil {
		sess.Delete("redirect_after_login")
		sess.Save()
		return redirectURL.(string)
	}

	return "/"
}

func (a *App) CSRFMiddleware() fiber.Handler {
	return csrf.New(csrf.Config{
		KeyLookup:         "form:_token",
		CookieName:        "csrf_token",
		CookieSameSite:    "Lax",
		CookieSecure:      false,
		CookieSessionOnly: true,
		CookieHTTPOnly:    true,
		Expiration:        24 * time.Hour,
		ContextKey:        "csrf_token",

		ErrorHandler: func(c *fiber.Ctx, err error) error {
			return c.Status(fiber.StatusForbidden).Render("errors/csrf", fiber.Map{
				"Title": "Security Error",
				"Error": "Invalid security token. Please refresh the page and try again.",
			}, "layouts/base")
		},
	})
}
