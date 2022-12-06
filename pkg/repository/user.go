package repository

import (
	"fmt"
	"github.com/jmoiron/sqlx"
)

type UserRepository struct {
	db *sqlx.DB
}

type User struct {
	ID       int
	Username string
	Email    string
	Password string
}

func NewUserRepository(db *sqlx.DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) InsertUser(user User) (int, error) {
	var id int

	err := r.db.Get(&id, "INSERT INTO \"user\" (username, email, password) VALUES ($1, $2, $3) RETURNING id", user.Username, user.Email, user.Password)
	if err != nil {
		return 0, err
	}

	fmt.Println(id)

	return id, nil
}
