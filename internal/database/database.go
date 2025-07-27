package database

import (
	"github.com/glebarez/sqlite"
	"github.com/mickgardner/blog/internal/config"
	"gorm.io/gorm"
	"log"
)

func StartDB(dbname string, config config.Config) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(dbname), &gorm.Config{})
	if err != nil {
		log.Fatalln("Database unable to be created: ", err)
	}
	if config.Env == "Development" {
		db.AutoMigrate()
	}
	return db
}
