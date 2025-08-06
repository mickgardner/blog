package main

import (
	"gorm.io/gorm"
)

type Article struct {
	Title string
	Slug  string
	Body  string
	gorm.Model
}

func (a *App) GetArticle(slug string) (*Article, error) {
	var article Article
	err := a.DB.Where("slug = ?", slug).First(&article).Error
	if err != nil {
		return nil, err
	}
	return &article, nil
}

func (a *App) GetAllArticles() ([]Article, error) {
	var articles []Article
	err := a.DB.Find(&articles).Error
	return articles, err
}
