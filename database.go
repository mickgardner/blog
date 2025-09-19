package main

import (
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"log"
	"time"
)

func SetupDatabase(config Config) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(config.DBName), &gorm.Config{})
	if err != nil {
		log.Fatalln("Database unable to be created: ", err)
	}
	if config.Env == "Development" {
		log.Println("Automigrating...")
		
		// Auto-migrate all tables
		db.AutoMigrate(Article{}, Page{}, NavigationItem{}, Session{}, VerificationCode{}, PasswordResetToken{}, User{}, EmailQueue{}, Invitation{})
	}

	return db
}


func (a *App) SeedDatabase() {
	log.Println("Seeding database...")

	// Create super admin user if configured and doesn't exist
	a.CreateSuperAdmin()

	// Seed default navigation items
	a.SeedDefaultNavigation()
	
	if a.Config.Env == "Development" {
		var count int64

		a.DB.Model(&Article{}).Count(&count)
		if count > 0 {
			return
		}
		
		// Get the super admin user to use as the author
		var superAdmin User
		err := a.DB.Where("is_admin = ?", true).First(&superAdmin).Error
		if err != nil {
			log.Printf("No admin user found for seeding articles: %v", err)
			return
		}
		
		now := time.Now()
		yesterday := now.AddDate(0, 0, -1)
		lastWeek := now.AddDate(0, 0, -7)
		
		articles := []Article{
			{
				Title:       "Welcome to My Blog",
				Slug:        "welcome-to-my-blog",
				Body:        "Welcome to my personal blog! This is where I'll be sharing my thoughts, experiences, and insights on various topics that interest me. From technology and programming to life experiences and random musings, you'll find a diverse range of content here. I hope you find something valuable and engaging in my posts. Feel free to reach out if you have any questions or want to discuss any of the topics I cover. Thanks for visiting!",
				AuthorID:    superAdmin.ID,
				PublishedAt: &lastWeek,
			},
			{
				Title:       "Learning Go Programming: A Journey",
				Slug:        "learning-go-programming",
				Body:        "Go is an amazing language for web development and backend services. In this article, I'll share some of the key concepts I've learned and tips that have helped me become more productive with Go. From understanding goroutines and channels to building web APIs with frameworks like Fiber, Go offers a great balance of simplicity and power. The language's focus on readability and performance makes it an excellent choice for modern applications. Whether you're building microservices, CLI tools, or web applications, Go provides the tools you need to get the job done efficiently.",
				AuthorID:    superAdmin.ID,
				PublishedAt: &yesterday,
			},
			{
				Title:       "Building Modern Web Applications",
				Slug:        "building-web-applications",
				Body:        "Web development has evolved significantly over the years, and today's applications require a thoughtful approach to architecture, user experience, and performance. In this post, I explore the key principles and technologies that make modern web applications successful. From choosing the right backend framework to implementing responsive design and ensuring security best practices, building web applications involves many considerations. I'll share insights from my experience building applications with Go, discussing database design, API development, authentication systems, and deployment strategies that have proven effective in real-world projects.",
				AuthorID:    superAdmin.ID,
				PublishedAt: &now,
			},
		}

		a.DB.Create(&articles)
	}
}

// GenerateSecurePassword is now in utils.go

func (a *App) CreateSuperAdmin() {
	if a.Config.AdminEmail == "" {
		log.Println("No ADMIN_EMAIL configured, skipping super admin creation")
		return
	}
	
	// Check if super admin already exists
	var existingAdmin User
	err := a.DB.Where("email_address = ? AND is_admin = ?", a.Config.AdminEmail, true).First(&existingAdmin).Error
	if err == nil {
		log.Printf("Super admin already exists: %s", existingAdmin.EmailAddress)
		return
	}
	
	// Check if any user with this email exists (but isn't admin)
	var existingUser User
	err = a.DB.Where("email_address = ?", a.Config.AdminEmail).First(&existingUser).Error
	if err == nil {
		// User exists but isn't admin, promote them
		log.Printf("Promoting existing user to super admin: %s", a.Config.AdminEmail)
		
		// Ensure they have a password (generate one if they don't)
		password := ""
		if existingUser.PasswordHash == "" {
			password = GenerateSecurePassword(16)
			passwordHash, err := HashPassword(password)
			if err != nil {
				log.Printf("Failed to hash admin password: %v", err)
				return
			}
			existingUser.PasswordHash = passwordHash
		}
		
		// Make them admin
		existingUser.IsAdmin = true
		existingUser.Active = true
		existingUser.EmailVerified = true
		
		err = a.DB.Save(&existingUser).Error
		if err != nil {
			log.Printf("Failed to promote user to super admin: %v", err)
			return
		}
		
		// Display credentials if password was generated
		if password != "" {
			a.displayAdminCredentials(a.Config.AdminEmail, password)
		} else {
			log.Printf("User %s promoted to super admin (existing password retained)", existingUser.EmailAddress)
		}
		return
	}
	
	// Generate secure password
	password := GenerateSecurePassword(16)
	passwordHash, err := HashPassword(password)
	if err != nil {
		log.Printf("Failed to hash admin password: %v", err)
		return
	}
	
	// Create super admin user
	adminUser := User{
		EmailAddress:  a.Config.AdminEmail,
		PasswordHash:  passwordHash,
		FullName:      "Super Administrator",
		Active:        true,
		IsAdmin:       true,
		EmailVerified: true, // Admin email is pre-verified
		RegisteredAt:  &time.Time{},
	}
	*adminUser.RegisteredAt = time.Now()
	
	err = a.DB.Create(&adminUser).Error
	if err != nil {
		log.Printf("Failed to create super admin: %v", err)
		return
	}
	
	a.displayAdminCredentials(a.Config.AdminEmail, password)
}

func (a *App) displayAdminCredentials(email, password string) {
	// Display credentials securely
	log.Println("=====================================")
	log.Println("SUPER ADMIN CREATED")
	log.Println("=====================================")
	log.Printf("Email:    %s", email)
	log.Printf("Password: %s", password)
	log.Println("=====================================")
	log.Println("IMPORTANT: Save these credentials now!")
	log.Println("This password will not be shown again.")
	log.Println("Login with your email address.")
	log.Println("=====================================")
}
