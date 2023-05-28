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
	r.HandleFunc("/users/{id}", routes.GetUserHandler).Methods("GET")
	r.HandleFunc("/users/{id}", routes.DeleteUserHandler).Methods("DELETE")
	r.HandleFunc("/users/{id}", routes.PutUserHandler).Methods("PUT")
	r.HandleFunc("/users/login", routes.LoginHandler).Methods("POST")
	r.HandleFunc("/users/register", routes.CreateUsersHandler).Methods("POST")
	r.HandleFunc("/users/confirm", routes.ConfirmUserHandler).Methods("POST")
	r.HandleFunc("/verify", routes.VerifyJWT).Methods("POST")

	r.HandleFunc("/apps", routes.GetAppsHandler).Methods("GET")
	r.HandleFunc("/apps/{id}", routes.GetAppHandler).Methods("GET")
	r.HandleFunc("/apps/{id}", routes.DeleteAppHandler).Methods("DELETE")
	r.HandleFunc("/apps/{id}", routes.PutAppHandler).Methods("PUT")
	r.HandleFunc("/apps/register", routes.CreateAppHandler).Methods("POST")

	http.ListenAndServe(":3000", r)
}
