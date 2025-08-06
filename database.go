package main

import (
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"log"
)

func SetupDatabase(config Config) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(config.DBName), &gorm.Config{})
	if err != nil {
		log.Fatalln("Database unable to be created: ", err)
	}
	if config.Env == "Development" {
		log.Println("Automigrating...")
		db.AutoMigrate(Article{}, VerificationCode{}, User{}, EmailQueue{})
	}

	return db
}

func (a *App) SeedDatabase() {
	if a.Config.Env == "Development" {
		log.Println("Seeding database...")
		var count int64

		a.DB.Model(&Article{}).Count(&count)
		if count > 0 {
			return
		}
		articles := []Article{
			{
				Title: "Welcome to My Blog",
				Slug:  "welcome-to-my-blog",
				Body:  "This is my first blog post. Welcome to my personal blog where I'll share thoughts and ideas",
			},
			{
				Title: "Learning Go Programming",
				Slug:  "learning-go-programming",
				Body:  "Go is an amazing language for web development. Here are some tips I've learned...",
			},
			{
				Title: "Building Web Applications",
				Slug:  "building-web-applications",
				Body:  "Web development with Go and Fiber is straightforward and powerful.",
			},
		}

		a.DB.Create(&articles)
	}
}
