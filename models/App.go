package models

import (
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type App struct {
	gorm.Model

	ID   uuid.UUID `gorm:"primaryKey;type:uuid;default:uuid_generate_v4()"`
	Name string    `gorm:"not null;type:varchar(100)" json:"name"`
}
