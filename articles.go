package main

import (
	"errors"
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

// GetFormattedCreatedAt returns a formatted creation date
func (article *Article) GetFormattedCreatedAt() string {
	return article.CreatedAt.Format("Jan 2, 2006 at 3:04 PM")
}

// GetFormattedUpdatedAt returns a formatted last update date
func (article *Article) GetFormattedUpdatedAt() string {
	return article.UpdatedAt.Format("Jan 2, 2006")
}

// GetFormattedPublishedAt returns a formatted publish date with time
func (article *Article) GetFormattedPublishedAt() string {
	if article.PublishedAt == nil {
		return "Not published"
	}
	return article.PublishedAt.Format("Jan 2, 2006 at 3:04 PM")
}

// GetPublishedArticles returns only published articles
func (a *App) GetPublishedArticles() ([]Article, error) {
	var articles []Article
	err := a.DB.Preload("Author").Where("published_at IS NOT NULL AND published_at <= ?", time.Now()).Order("published_at DESC").Find(&articles).Error
	return articles, err
}

// GetAllArticlesForManagement returns all articles for admin management
func (a *App) GetAllArticlesForManagement() ([]Article, error) {
	var articles []Article
	err := a.DB.Preload("Author").Order("updated_at DESC").Find(&articles).Error
	return articles, err
}

// GetArticleByID returns an article by ID with author preloaded
func (a *App) GetArticleByID(id string) (*Article, error) {
	var article Article
	err := a.DB.Preload("Author").Where("id = ?", id).First(&article).Error
	if err != nil {
		return nil, err
	}
	return &article, nil
}

// ValidateSlugUnique checks if a slug is unique (excluding current article if updating)
func (a *App) ValidateSlugUnique(slug string, excludeID uint) error {
	var count int64
	query := a.DB.Model(&Article{}).Where("slug = ?", slug)
	if excludeID > 0 {
		query = query.Where("id != ?", excludeID)
	}
	query.Count(&count)

	if count > 0 {
		return errors.New("slug already exists")
	}
	return nil
}

// validateSlugUniqueInTx checks slug uniqueness within a transaction
func (a *App) validateSlugUniqueInTx(tx *gorm.DB, slug string, excludeID uint) error {
	var count int64
	query := tx.Model(&Article{}).Where("slug = ?", slug)
	if excludeID > 0 {
		query = query.Where("id != ?", excludeID)
	}
	query.Count(&count)

	if count > 0 {
		return errors.New("slug already exists")
	}
	return nil
}

// CreateArticle creates a new article with transaction support
func (a *App) CreateArticle(title, slug, body string, authorID uint, publish bool) (*Article, error) {
	var article *Article

	// Use transaction to ensure atomicity
	err := a.DB.Transaction(func(tx *gorm.DB) error {
		// Validate slug uniqueness within transaction
		err := a.validateSlugUniqueInTx(tx, slug, 0)
		if err != nil {
			return err
		}

		article = &Article{
			Title:    title,
			Slug:     slug,
			Body:     body,
			AuthorID: authorID,
		}

		if publish {
			now := time.Now()
			article.PublishedAt = &now
		}

		err = tx.Create(article).Error
		if err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return article, nil
}

// UpdateArticle updates an existing article with transaction support
func (a *App) UpdateArticle(id uint, title, slug, body string, publish bool) (*Article, error) {
	var article *Article

	// Use transaction to ensure atomicity
	err := a.DB.Transaction(func(tx *gorm.DB) error {
		// Get existing article within transaction
		var existingArticle Article
		err := tx.Where("id = ?", id).First(&existingArticle).Error
		if err != nil {
			return err
		}

		// Validate slug uniqueness if changed
		if existingArticle.Slug != slug {
			err := a.validateSlugUniqueInTx(tx, slug, id)
			if err != nil {
				return err
			}
		}

		// Update fields
		existingArticle.Title = title
		existingArticle.Slug = slug
		existingArticle.Body = body

		// Handle publishing status
		if publish && existingArticle.PublishedAt == nil {
			// Publishing for the first time
			now := time.Now()
			existingArticle.PublishedAt = &now
		} else if !publish {
			// Unpublishing
			existingArticle.PublishedAt = nil
		}

		err = tx.Save(&existingArticle).Error
		if err != nil {
			return err
		}

		article = &existingArticle
		return nil
	})

	if err != nil {
		return nil, err
	}

	return article, nil
}

// PublishArticle publishes an article
func (a *App) PublishArticle(id uint) error {
	now := time.Now()
	return a.DB.Model(&Article{}).Where("id = ?", id).Update("published_at", &now).Error
}

// UnpublishArticle unpublishes an article
func (a *App) UnpublishArticle(id uint) error {
	return a.DB.Model(&Article{}).Where("id = ?", id).Update("published_at", nil).Error
}

// DeleteArticle deletes an article
func (a *App) DeleteArticle(id uint) error {
	return a.DB.Where("id = ?", id).Delete(&Article{}).Error
}
