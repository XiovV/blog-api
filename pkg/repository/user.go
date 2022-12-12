package repository

import (
	"github.com/jmoiron/sqlx"
)

type UserRepository struct {
	db *sqlx.DB
}

const (
	normalRole = iota + 1
	moderatorRole
	adminRole
)

type User struct {
	ID        int
	Username  string
	Email     string
	Password  string
	MFASecret []byte `db:"mfa_secret"`
	Role      string
}

func NewUserRepository(db *sqlx.DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) InsertUser(user User) (int, error) {
	var id int

	err := r.db.Get(&id, "INSERT INTO \"user\" (username, email, password, role) VALUES ($1, $2, $3, $4) RETURNING id", user.Username, user.Email, user.Password, normalRole)
	if err != nil {
		return 0, err
	}

	return id, nil
}

func (r *UserRepository) InsertMfaSecret(userId int, secret []byte) error {
	_, err := r.db.Exec("UPDATE \"user\" SET mfa_secret = $1 WHERE id = $2", secret, userId)
	if err != nil {
		return err
	}

	return nil
}

func (r *UserRepository) FindUserByID(id int) (User, error) {
	var user User

	err := r.db.Get(&user, "SELECT \"user\".id, username, email, password, mfa_secret, role.name as role FROM \"user\" INNER JOIN role ON \"user\".role = role.id WHERE \"user\".id = $1", id)
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
