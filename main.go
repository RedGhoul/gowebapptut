package main

import (
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

func main() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatalf("Some error occured. Err: %s", err)
	}
	// Get the database connection string from the environment variable
	dbURL := os.Getenv("DB_URL")
	log.Println(dbURL)
	if dbURL == "" {
		log.Fatal("DB_URL is required")
	}

	// Create a new DB instance
	db, err := NewDB(dbURL)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Create a new Handler instance
	handler := NewHandler(db)

	// Create a new ServeMux instance
	mux := http.NewServeMux()

	// Register the handler functions with the ServeMux
	mux.HandleFunc("/", handler.Index)
	mux.HandleFunc("/signup", handler.Signup)
	mux.HandleFunc("/login", handler.Login)
	mux.HandleFunc("/logout", handler.Logout)
	mux.HandleFunc("/home", handler.Home)
	mux.HandleFunc("/api", handler.API)

	// Start the HTTP server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("Listening on port %s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}
