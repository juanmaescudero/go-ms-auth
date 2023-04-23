package routes

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/juanmaescudero/go-ms-auth/db"
	"github.com/juanmaescudero/go-ms-auth/models"
)

func GetAppsHandler(w http.ResponseWriter, r *http.Request) {
	var apps []models.App
	db.DB.Find(&apps)
	json.NewEncoder(w).Encode(&apps)
}

func GetAppHandler(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	idString := params["id"]

	id, err := uuid.Parse(idString)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Invalid ID"))
		return
	}

	// Get app from database
	var app models.App
	result := db.DB.First(&app, id)
	if result.RowsAffected == 0 {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("App not found"))
		return
	}

	// Return user as JSON response
	json.NewEncoder(w).Encode(&app)
}

func CreateAppHandler(w http.ResponseWriter, r *http.Request) {
	var app models.App
	json.NewDecoder(r.Body).Decode(&app)

	createdApp := db.DB.Create(&app)
	err := createdApp.Error
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
	}

	json.NewEncoder(w).Encode(&app)
}

func DeleteAppHandler(w http.ResponseWriter, r *http.Request) {
	var app models.App
	params := mux.Vars(r)
	idString := params["id"]

	id, err := uuid.Parse(idString)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Invalid ID"))
		return
	}

	// Delete user from database
	result := db.DB.Delete(&app, id)
	if result.RowsAffected == 0 {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("App not found"))
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("App deleted successfully"))
}

func PutAppHandler(w http.ResponseWriter, r *http.Request) {
	var app models.App
	params := mux.Vars(r)
	idString := params["id"]

	json.NewDecoder(r.Body).Decode(&app)

	id, err := uuid.Parse(idString)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Invalid ID"))
		return
	}

	app.ID = id

	// Find existing user on ddbb
	existingUser := db.DB.First(&models.App{}, app.ID)

	// check if user exist
	if existingUser.RowsAffected == 0 {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("User not found"))
		return
	}

	// update user
	db.DB.Model(&app).Updates(&app)

	// return updated user
	json.NewEncoder(w).Encode(&app)
}
