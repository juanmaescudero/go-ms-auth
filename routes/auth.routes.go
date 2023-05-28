package routes

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/juanmaescudero/go-ms-auth/db"
	"github.com/juanmaescudero/go-ms-auth/mails"
	"github.com/juanmaescudero/go-ms-auth/models"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

func GetUsersHandler(w http.ResponseWriter, r *http.Request) {
	var users []models.User
	db.DB.Preload("App").Find(&users)
	json.NewEncoder(w).Encode(&users)
}

func GetUserHandler(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	idString := params["id"]

	id, err := uuid.Parse(idString)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Invalid ID"))
		return
	}

	// Get user from database
	var user models.User
	result := db.DB.Preload("App").First(&user, id)
	if result.RowsAffected == 0 {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("User not found"))
		return
	}

	// Return user as JSON response
	json.NewEncoder(w).Encode(&user)
}

func CreateUsersHandler(w http.ResponseWriter, r *http.Request) {
	var user models.User
	json.NewDecoder(r.Body).Decode(&user)

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}

	user.Password = string(hashedPassword)

	// Compruebe si ya existe un usuario con el mismo nombre de usuario o correo electrónico en la misma aplicación
	var existingUser models.User
	err = db.DB.Where("app_id = ? AND (username = ? OR email = ?)", user.AppID, user.Username, user.Email).First(&existingUser).Error
	if err == nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Username or email exists in this app"))
		return
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}

	// Cree el usuario
	createdUser := db.DB.Preload("App").Create(&user)
	err = createdUser.Error
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}

	json.NewEncoder(w).Encode(&user)
	mails.ConfirmationMail(user.Email, user.ConfirmationToken.String())
}

func DeleteUserHandler(w http.ResponseWriter, r *http.Request) {
	var user models.User
	params := mux.Vars(r)
	idString := params["id"]

	id, err := uuid.Parse(idString)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Invalid ID"))
		return
	}

	// Delete user from database
	result := db.DB.Delete(&user, id)
	if result.RowsAffected == 0 {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("User not found"))
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("User deleted successfully"))
}

func PutUserHandler(w http.ResponseWriter, r *http.Request) {
	var user models.User
	params := mux.Vars(r)
	idString := params["id"]

	json.NewDecoder(r.Body).Decode(&user)

	id, err := uuid.Parse(idString)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Invalid ID"))
		return
	}

	user.ID = id

	// Find existing user on ddbb
	existingUser := db.DB.First(&models.User{}, user.ID)

	// check if user exist
	if existingUser.RowsAffected == 0 {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("User not found"))
		return
	}

	// update user
	db.DB.Model(&user).Updates(&user)

	// return updated user
	json.NewEncoder(w).Encode(&user)
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var user models.User

	json.NewDecoder(r.Body).Decode(&user)

	rawPass := user.Password

	// Find user by username
	db.DB.Where("username = ?", user.Username).First(&user)

	// Check if user exists and password is correct
	if bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(rawPass)) != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Invalid email or password"))
		return
	}

	// Create JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": user.ID,
		"exp":     time.Now().Add(time.Hour * 24).Unix(),
	})

	// Sign JWT token with secret key
	tokenString, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}

	// Return JWT token
	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

func CheckPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func VerifyJWT(w http.ResponseWriter, r *http.Request) {
	var body map[string]string

	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Invalid request body"))
		return
	}

	tokenString := body["token"]
	if tokenString == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Token not provided"))
		return
	}

	// Parse JWT token without verifying the signature
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Make sure signing method is HMAC with SHA256
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		// Return secret key as the key for validating the signature
		return []byte(os.Getenv("JWT_SECRET")), nil
	})

	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Invalid token"))
		return
	}

	// Check if token is valid and return the claims
	if _, ok := token.Claims.(jwt.MapClaims); !ok || !token.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Invalid token"))
		return
	}

	// Return JWT token
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Token valid"))
}

func ConfirmUserHandler(w http.ResponseWriter, r *http.Request) {
	var confirmUserRequest models.ConfirmUserRequest
	json.NewDecoder(r.Body).Decode(&confirmUserRequest)

	var user models.User
	result := db.DB.Where(&models.User{Email: confirmUserRequest.Email}).First(&user)
	if result.Error != nil {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("User not found"))
		return
	}

	if user.Active {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("User already active"))
		return
	}

	if user.ConfirmationToken != confirmUserRequest.Token {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Invalid confirmation token"))
		return
	}

	user.Active = true
	db.DB.Save(&user)

	json.NewEncoder(w).Encode(&user)
}
