package models

import (
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type App struct {
	gorm.Model

	ID   uuid.UUID `json:"id" gorm:"type:uuid;default:uuid_generate_v4()"`
	Name string
}
