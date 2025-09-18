package main

import (
	"errors"
	"gorm.io/gorm"
	"strings"
)

type Page struct {
	Title    string
	Slug     string `gorm:"unique"`
	Body     string
	AuthorID uint `gorm:"index"`
	Author   User `gorm:"foreignKey:AuthorID"`
	Active   bool `gorm:"default:true"`
	gorm.Model
}

// GetFormattedCreatedAt returns a formatted creation date
func (page *Page) GetFormattedCreatedAt() string {
	return page.CreatedAt.Format("January 2, 2006 at 3:04 PM")
}

// GetFormattedUpdatedAt returns a formatted update date
func (page *Page) GetFormattedUpdatedAt() string {
	return page.UpdatedAt.Format("January 2, 2006 at 3:04 PM")
}

// Page CRUD operations

func (a *App) GetPage(slug string) (*Page, error) {
	var page Page
	err := a.DB.Preload("Author").Where("slug = ? AND active = ?", slug, true).First(&page).Error
	if err != nil {
		return nil, err
	}
	return &page, nil
}

func (a *App) GetPageByID(id string) (*Page, error) {
	var page Page
	err := a.DB.Preload("Author").Where("id = ?", id).First(&page).Error
	if err != nil {
		return nil, err
	}
	return &page, nil
}

func (a *App) GetAllPages() ([]Page, error) {
	var pages []Page
	err := a.DB.Preload("Author").Order("title ASC").Find(&pages).Error
	return pages, err
}

func (a *App) GetActivePages() ([]Page, error) {
	var pages []Page
	err := a.DB.Preload("Author").Where("active = ?", true).Order("title ASC").Find(&pages).Error
	return pages, err
}

func (a *App) CreatePage(title, slug, body string, authorID uint) (*Page, error) {
	// Use transaction for atomic operation
	var page *Page
	err := a.DB.Transaction(func(tx *gorm.DB) error {
		// Check if slug already exists
		var existingPage Page
		err := tx.Where("slug = ?", slug).First(&existingPage).Error
		if err == nil {
			return errors.New("page with this slug already exists")
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}

		// Validate that slug doesn't conflict with existing routes
		if !isValidPageSlug(slug) {
			return errors.New("page slug conflicts with existing routes")
		}

		// Create the page
		page = &Page{
			Title:    title,
			Slug:     slug,
			Body:     body,
			AuthorID: authorID,
			Active:   true,
		}

		err = tx.Create(page).Error
		if err != nil {
			return err
		}

		// Reload with author
		err = tx.Preload("Author").Where("id = ?", page.ID).First(page).Error
		return err
	})

	return page, err
}

func (a *App) UpdatePage(pageID uint, title, slug, body string) error {
	return a.DB.Transaction(func(tx *gorm.DB) error {
		// Check if slug already exists (excluding current page)
		var existingPage Page
		err := tx.Where("slug = ? AND id != ?", slug, pageID).First(&existingPage).Error
		if err == nil {
			return errors.New("page with this slug already exists")
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}

		// Validate that slug doesn't conflict with existing routes
		if !isValidPageSlug(slug) {
			return errors.New("page slug conflicts with existing routes")
		}

		// Update the page
		err = tx.Model(&Page{}).Where("id = ?", pageID).Updates(Page{
			Title: title,
			Slug:  slug,
			Body:  body,
		}).Error

		return err
	})
}

func (a *App) ActivatePage(pageID uint) error {
	return a.DB.Model(&Page{}).Where("id = ?", pageID).Update("active", true).Error
}

func (a *App) DeactivatePage(pageID uint) error {
	return a.DB.Model(&Page{}).Where("id = ?", pageID).Update("active", false).Error
}

func (a *App) DeletePage(pageID uint) error {
	return a.DB.Delete(&Page{}, pageID).Error
}

// Route validation to prevent conflicts with existing routes
func isValidPageSlug(slug string) bool {
	// Reserved routes that pages cannot use
	reservedRoutes := []string{
		"article", "articles",
		"author", "authors",
		"admin",
		"login", "logout", "register",
		"dashboard", "profile",
		"forgot-password", "reset-password",
		"verify",
		"static", "uploads",
		"api",
	}

	// Convert to lowercase for comparison
	slugLower := strings.ToLower(strings.TrimSpace(slug))

	// Check if slug matches any reserved route
	for _, reserved := range reservedRoutes {
		if slugLower == reserved {
			return false
		}
	}

	// Check if slug starts with reserved prefixes
	reservedPrefixes := []string{
		"admin/",
		"api/",
		"static/",
	}

	for _, prefix := range reservedPrefixes {
		if strings.HasPrefix(slugLower, prefix) {
			return false
		}
	}

	// Additional validation - slug should be URL safe
	if slugLower != slug {
		return false // Should be lowercase
	}

	// Check for valid characters (letters, numbers, hyphens only)
	for _, char := range slug {
		if !((char >= 'a' && char <= 'z') ||
			 (char >= '0' && char <= '9') ||
			 char == '-') {
			return false
		}
	}

	// Must not start or end with hyphen
	if strings.HasPrefix(slug, "-") || strings.HasSuffix(slug, "-") {
		return false
	}

	// Must not be empty
	if len(slug) == 0 {
		return false
	}

	return true
}