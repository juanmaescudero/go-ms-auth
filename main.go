package main

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/juanmaescudero/go-ms-auth/db"
	"github.com/juanmaescudero/go-ms-auth/models"
	"github.com/juanmaescudero/go-ms-auth/routes"
)

func main() {
	db.DBConnnection()

	db.DB.AutoMigrate(models.App{})
	db.DB.AutoMigrate(models.User{})

	r := mux.NewRouter()

	r.HandleFunc("/users", routes.GetUsersHandler).Methods("GET")
	r.HandleFunc("/users", routes.PostUsersHandler).Methods("POST")
	r.HandleFunc("/users/{id}", routes.GetUserHandler).Methods("GET")
	r.HandleFunc("/users/{id}", routes.DeleteUserHandler).Methods("DELETE")
	r.HandleFunc("/users/{id}", routes.PutUserHandler).Methods("PUT")

	http.ListenAndServe(":3000", r)
}
