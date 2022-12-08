package repository

import (
	"database/sql"
	"fmt"
	"github.com/jmoiron/sqlx"
)

type UserRepository struct {
	db *sqlx.DB
}

type User struct {
	ID        int
	Username  string
	Email     string
	Password  string
	MFASecret sql.NullString `db:"mfa_secret"`
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

func (r *UserRepository) FindUserByID(id int) (User, error) {
	var user User

	err := r.db.Get(&user, "SELECT * FROM \"user\" WHERE id = $1", id)
	if err != nil {
		return User{}, err
	}

	return user, nil
}

func (r *UserRepository) FindUserByUsername(username string) (User, error) {
	var user User

	err := r.db.Get(&user, "SELECT * FROM \"user\" WHERE username = $1", username)
	if err != nil {
		return User{}, err
	}

	return user, nil
}
