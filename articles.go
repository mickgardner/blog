package main

import (
	"gorm.io/gorm"
	"strings"
	"time"
)

type Article struct {
	Title       string
	Slug        string
	Body        string
	AuthorID    uint  `gorm:"index"`
	Author      User  `gorm:"foreignKey:AuthorID"`
	PublishedAt *time.Time
	gorm.Model
}

func (a *App) GetArticle(slug string) (*Article, error) {
	var article Article
	err := a.DB.Preload("Author").Where("slug = ?", slug).First(&article).Error
	if err != nil {
		return nil, err
	}
	return &article, nil
}

func (a *App) GetAllArticles() ([]Article, error) {
	var articles []Article
	err := a.DB.Preload("Author").Order("published_at DESC").Find(&articles).Error
	return articles, err
}

// GetExcerpt returns a preview of the article body (first few sentences)
func (article *Article) GetExcerpt() string {
	maxLength := 180 // Default excerpt length
	
	// Remove HTML tags (basic cleanup)
	body := strings.ReplaceAll(article.Body, "<", "&lt;")
	body = strings.ReplaceAll(body, ">", "&gt;")
	
	// If body is shorter than maxLength, return it all
	if len(body) <= maxLength {
		return body
	}
	
	// Find the last complete word within maxLength
	excerpt := body[:maxLength]
	lastSpace := strings.LastIndex(excerpt, " ")
	if lastSpace > 0 {
		excerpt = excerpt[:lastSpace]
	}
	
	return excerpt + "..."
}

// IsPublished checks if the article has been published
func (article *Article) IsPublished() bool {
	return article.PublishedAt != nil && article.PublishedAt.Before(time.Now())
}

// GetFormattedPublishDate returns a nicely formatted publish date
func (article *Article) GetFormattedPublishDate() string {
	if article.PublishedAt == nil {
		return "Draft"
	}
	return article.PublishedAt.Format("January 2, 2006")
}

// GetPublishedArticles returns only published articles
func (a *App) GetPublishedArticles() ([]Article, error) {
	var articles []Article
	err := a.DB.Preload("Author").Where("published_at IS NOT NULL AND published_at <= ?", time.Now()).Order("published_at DESC").Find(&articles).Error
	return articles, err
}
