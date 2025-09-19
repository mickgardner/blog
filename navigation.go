package main

import (
	"errors"
	"gorm.io/gorm"
	"strings"
)

type NavigationItem struct {
	Title    string
	URL      string
	Order    int    `gorm:"default:0"`
	Active   bool   `gorm:"default:true"`
	Target   string `gorm:"default:'_self'"` // _self or _blank
	gorm.Model
}

// Navigation CRUD operations

func (a *App) GetActiveNavigationItems() ([]NavigationItem, error) {
	var items []NavigationItem
	err := a.DB.Where("active = ?", true).Order("order ASC, id ASC").Find(&items).Error
	return items, err
}

func (a *App) GetAllNavigationItems() ([]NavigationItem, error) {
	var items []NavigationItem
	err := a.DB.Order("order ASC, id ASC").Find(&items).Error
	return items, err
}

func (a *App) GetNavigationItemByID(id string) (*NavigationItem, error) {
	var item NavigationItem
	err := a.DB.Where("id = ?", id).First(&item).Error
	if err != nil {
		return nil, err
	}
	return &item, nil
}

func (a *App) CreateNavigationItem(title, url string, order int, target string) (*NavigationItem, error) {
	// Validate inputs
	title = strings.TrimSpace(title)
	url = strings.TrimSpace(url)
	target = strings.TrimSpace(target)

	if title == "" {
		return nil, errors.New("title is required")
	}

	if url == "" {
		return nil, errors.New("URL is required")
	}

	// Validate target
	if target != "_self" && target != "_blank" {
		target = "_self"
	}

	// Validate URL format
	if !isValidNavigationURL(url) {
		return nil, errors.New("invalid URL format")
	}

	// Use transaction for atomic operation
	var item *NavigationItem
	err := a.DB.Transaction(func(tx *gorm.DB) error {
		// If no order specified, set to last position
		if order <= 0 {
			var maxOrder int
			tx.Model(&NavigationItem{}).Select("COALESCE(MAX(order), 0)").Scan(&maxOrder)
			order = maxOrder + 1
		}

		// Create the navigation item
		item = &NavigationItem{
			Title:  title,
			URL:    url,
			Order:  order,
			Target: target,
			Active: true,
		}

		return tx.Create(item).Error
	})

	return item, err
}

func (a *App) UpdateNavigationItem(itemID uint, title, url string, order int, target string, active bool) error {
	// Validate inputs
	title = strings.TrimSpace(title)
	url = strings.TrimSpace(url)
	target = strings.TrimSpace(target)

	if title == "" {
		return errors.New("title is required")
	}

	if url == "" {
		return errors.New("URL is required")
	}

	// Validate target
	if target != "_self" && target != "_blank" {
		target = "_self"
	}

	// Validate URL format
	if !isValidNavigationURL(url) {
		return errors.New("invalid URL format")
	}

	return a.DB.Transaction(func(tx *gorm.DB) error {
		// Update the navigation item
		return tx.Model(&NavigationItem{}).Where("id = ?", itemID).Updates(NavigationItem{
			Title:  title,
			URL:    url,
			Order:  order,
			Target: target,
			Active: active,
		}).Error
	})
}

func (a *App) UpdateNavigationOrder(itemID uint, newOrder int) error {
	return a.DB.Model(&NavigationItem{}).Where("id = ?", itemID).Update("order", newOrder).Error
}

func (a *App) ToggleNavigationItem(itemID uint) error {
	return a.DB.Model(&NavigationItem{}).Where("id = ?", itemID).Update("active", gorm.Expr("NOT active")).Error
}

func (a *App) DeleteNavigationItem(itemID uint) error {
	return a.DB.Delete(&NavigationItem{}, itemID).Error
}

// URL validation for navigation items
func isValidNavigationURL(url string) bool {
	url = strings.TrimSpace(url)

	if url == "" {
		return false
	}

	// Allow root path
	if url == "/" {
		return true
	}

	// Allow external URLs (http/https)
	if strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://") {
		return true
	}

	// Allow relative URLs starting with /
	if strings.HasPrefix(url, "/") {
		// Check for valid characters in path
		for _, char := range url[1:] { // Skip the leading /
			if !((char >= 'a' && char <= 'z') ||
				 (char >= 'A' && char <= 'Z') ||
				 (char >= '0' && char <= '9') ||
				 char == '-' || char == '_' || char == '/' || char == '.' || char == '?') {
				return false
			}
		}
		return true
	}

	// Allow anchor links
	if strings.HasPrefix(url, "#") {
		return true
	}

	return false
}

// Helper function to seed default navigation items
func (a *App) SeedDefaultNavigation() error {
	// Check if navigation items already exist
	var count int64
	a.DB.Model(&NavigationItem{}).Count(&count)

	if count > 0 {
		return nil // Already seeded
	}

	// Create default navigation items
	defaultItems := []NavigationItem{
		{Title: "Home", URL: "/", Order: 1, Active: true, Target: "_self"},
	}

	for _, item := range defaultItems {
		if err := a.DB.Create(&item).Error; err != nil {
			return err
		}
	}

	return nil
}