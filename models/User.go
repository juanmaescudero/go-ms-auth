package models

import (
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model

	ID                uuid.UUID `gorm:"type:uuid;default:uuid_generate_v4()"`
	Username          string    `gorm:"not null;type:varchar(100)" json:"username"`
	Password          string    `gorm:"not null" json:"password"`
	Email             string    `gorm:"not null" json:"email"`
	App               App       `gorm:"foreignKey:AppID"`
	AppID             uuid.UUID `gorm:"not null;type:uuid" json:"appId" sql:"type:uuid REFERENCES apps(id)"`
	RequestCount      int64     `gorm:"not null;default:0" json:"requestCount"`
	Active            bool      `gorm:"not null;default:false" json:"active"`
	ConfirmationToken uuid.UUID `gorm:"type:uuid;default:uuid_generate_v4()" json:"confirmationToken"`
}

type ConfirmUserRequest struct {
	Email string    `gorm:"not null" json:"email"`
	Token uuid.UUID `gorm:"type:uuid" json:"token"`
}
