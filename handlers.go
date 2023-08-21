package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

type Handler struct {
	db *DB
}

func NewHandler(db *DB) *Handler {
	return &Handler{db}
}

func (h *Handler) Index(w http.ResponseWriter, r *http.Request) {
	// Parse and execute the index template
	tmpl := template.Must(template.ParseFiles("templates/index.html"))
	err := tmpl.Execute(w, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (h *Handler) Signup(w http.ResponseWriter, r *http.Request) {
	// Check if the request method is GET or POST
	switch r.Method {
	case http.MethodGet:
		// Parse and execute the signup template
		tmpl := template.Must(template.ParseFiles("templates/signup.html"))
		err := tmpl.Execute(w, nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	case http.MethodPost:
		// Parse and validate the form input
		err := r.ParseForm()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		username := r.FormValue("username")
		password := r.FormValue("password")
		if username == "" || password == "" {
			http.Error(w, "Username and password are required", http.StatusBadRequest)
			return
		}

		// Create a new user in the database
		_, err = h.db.CreateUser(username, password)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Redirect to the login page with a success message
		http.Redirect(w, r, "/login?success=You have signed up successfully", http.StatusSeeOther)
	default:
		// Return a method not allowed error
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	// Check if the request method is GET or POST
	switch r.Method {
	case http.MethodGet:
		// Parse and execute the login template
		tmpl := template.Must(template.ParseFiles("templates/login.html"))
		data := map[string]interface{}{
			"Success": r.URL.Query().Get("success"),
		}
		err := tmpl.Execute(w, data)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	case http.MethodPost:
		// Parse and validate the form input
		err := r.ParseForm()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		username := r.FormValue("username")
		password := r.FormValue("password")
		if username == "" || password == "" {
			http.Error(w, "Username and password are required", http.StatusBadRequest)
			return
		}

		// Get the user by username from the database
		user, err := h.db.GetUserByUsername(username)
		if err != nil {
			if err == sql.ErrNoRows {
				// Return a not found error if the user does not exist
				http.Error(w, "User not found", http.StatusNotFound)
				return
			}
			// Return an internal server error otherwise
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Compare the hashed password with the input password
		err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
		if err != nil {
			// Return an unauthorized error if the password does not match
			http.Error(w, "Invalid password", http.StatusUnauthorized)
			return
		}

		// Create a JWT token for authentication
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"id":       user.ID,
			"username": user.Username,
			"exp":      time.Now().Add(24 * time.Hour).Unix(),
		})
		secret := os.Getenv("JWT_SECRET")
		tokenString, err := token.SignedString([]byte(secret))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Set a cookie with the token in the response
		cookie := &http.Cookie{
			Name:     "token",
			Value:    tokenString,
			Expires:  time.Now().Add(24 * time.Hour),
			HttpOnly: true,
			Path:     "/",
		}
		http.SetCookie(w, cookie)

		// Redirect to the home page with a success message
		http.Redirect(w, r, "/home?success=You have logged in successfully", http.StatusSeeOther)
	default:
		// Return a method not allowed error
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
}

func (h *Handler) Home(w http.ResponseWriter, r *http.Request) {
	// Check if the request method is GET
	if r.Method != http.MethodGet {
		// Return a method not allowed error
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get the cookie with the token from the request
	cookie, err := r.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			// Return an unauthorized error if the cookie does not exist
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		// Return an internal server error otherwise
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Parse and validate the token from the cookie
	tokenString := cookie.Value
	secret := os.Getenv("JWT_SECRET")
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Check if the signing method is valid
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		// Return the secret key as the verification key
		return []byte(secret), nil
	})
	if err != nil {
		// Return an unauthorized error if the token is invalid
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Get the claims from the token
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		// Return an unauthorized error if the claims are invalid
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Get the username from the claims
	username, ok := claims["username"].(string)
	if !ok {
		// Return an internal server error if the username is missing or not a string
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Parse and execute the home template
	tmpl := template.Must(template.ParseFiles("templates/home.html"))
	data := map[string]interface{}{
		"Success":  r.URL.Query().Get("success"),
		"Username": username,
	}
	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	// Check if the request method is GET
	if r.Method != http.MethodGet {
		// Return a method not allowed error
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Clear the cookie with the token in the response
	cookie := &http.Cookie{
		Name:     "token",
		Value:    "",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Path:     "/",
	}
	http.SetCookie(w, cookie)

	// Redirect to the index page with a success message
	http.Redirect(w, r, "/?success=You have logged out successfully", http.StatusSeeOther)
}

func (h *Handler) API(w http.ResponseWriter, r *http.Request) {
	// Check if the request method is GET
	if r.Method != http.MethodGet {
		// Return a method not allowed error
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get the cookie with the token from the request
	cookie, err := r.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			// Return an unauthorized error if the cookie does not exist
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		// Return an internal server error otherwise
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Parse and validate the token from the cookie
	tokenString := cookie.Value
	secret := os.Getenv("JWT_SECRET")
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Check if the signing method is valid
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		// Return the secret key as the verification key
		return []byte(secret), nil
	})
	if err != nil {
		// Return an unauthorized error if the token is invalid
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Get the claims from the token
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		// Return an unauthorized error if the claims are invalid
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Get the username from the claims
	username, ok := claims["username"].(string)
	if !ok {
		// Return an internal server error if the username is missing
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Get some data from the database using the user id
	user, err := h.db.GetUserByUsername(username)
	if err != nil {
		// Return an internal server error if there is an error getting the data
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	user.Password = ""
	// Encode and write the data as JSON to the response
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(user)
	if err != nil {
		// Return an internal server error if there is an error encoding the data
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
