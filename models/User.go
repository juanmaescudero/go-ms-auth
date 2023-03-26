package models

import (
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model

	ID       uuid.UUID `gorm:"type:uuid;default:uuid_generate_v4()"`
	Username string    `gorm:"not null;type:varchar(100)" json:"username"`
	Password string    `gorm:"not null" json:"password"`
	Email    string    `gorm:"not null" json:"email"`
	AppId    string    `gorm:"not null" json:"appId"`
}
