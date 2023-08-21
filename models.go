package main

import (
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type DB struct {
	*sqlx.DB
}
type User struct {
	ID        int       `db:"id"`
	Username  string    `db:"username"`
	Password  string    `db:"password"`
	CreatedAt time.Time `db:"created_at"`
}

func NewDB(dbURL string) (*DB, error) {
	db, err := sqlx.Open("postgres", dbURL)
	if err != nil {
		return nil, err
	}
	return &DB{db}, nil
}

func (db *DB) CreateUser(username, password string) (*User, error) {
	// Hash the password using bcrypt
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	// Create a new user in the database
	user := &User{
		Username: username,
		Password: string(hashedPassword),
	}
	query := "INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id, created_at"
	err = db.QueryRowx(query, user.Username, user.Password).StructScan(user)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (db *DB) GetUserByUsername(username string) (*User, error) {
	// Get the user by username from the database
	user := &User{}
	query := "SELECT * FROM users WHERE username = $1"
	err := db.Get(user, query, username)
	if err != nil {
		return nil, err
	}
	return user, nil
}
