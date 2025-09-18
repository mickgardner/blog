package main

import (
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/csrf"
	"github.com/gofiber/fiber/v2/middleware/limiter"
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
	// Set secure cookies in production
	cookieSecure := a.Config.Env != "Development"

	return csrf.New(csrf.Config{
		KeyLookup:         "form:_token",
		CookieName:        "csrf_token",
		CookieSameSite:    "Lax",
		CookieSecure:      cookieSecure,
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

func (a *App) RequireAdmin(c *fiber.Ctx) error {
	user, err := a.GetCurrentUser(c)
	if err != nil || !user.IsAdmin {
		return c.Status(403).Render("errors/403", fiber.Map{
			"Title": "Access Denied",
			"Error": "You must be an administrator to access this page.",
		}, "layouts/base")
	}
	return c.Next()
}

// AuthRateLimiter provides rate limiting for authentication endpoints
func (a *App) AuthRateLimiter() fiber.Handler {
	return limiter.New(limiter.Config{
		Max:        5,                     // 5 attempts
		Expiration: 15 * time.Minute,     // per 15 minutes
		KeyGenerator: func(c *fiber.Ctx) string {
			// Rate limit by IP address
			return c.IP()
		},
		LimitReached: func(c *fiber.Ctx) error {
			return c.Status(429).Render("errors/rate-limit", fiber.Map{
				"Title": "Too Many Attempts",
				"Error": "Too many login attempts. Please try again in 15 minutes.",
			}, "layouts/base")
		},
	})
}

// PasswordResetRateLimiter provides stricter rate limiting for password reset
func (a *App) PasswordResetRateLimiter() fiber.Handler {
	return limiter.New(limiter.Config{
		Max:        3,                     // 3 attempts
		Expiration: 60 * time.Minute,     // per hour
		KeyGenerator: func(c *fiber.Ctx) string {
			return c.IP()
		},
		LimitReached: func(c *fiber.Ctx) error {
			return c.Status(429).Render("errors/rate-limit", fiber.Map{
				"Title": "Too Many Password Reset Attempts",
				"Error": "Too many password reset attempts. Please try again in 1 hour.",
			}, "layouts/base")
		},
	})
}
