package repository

import "errors"

var (
	ErrUniqueViolation = errors.New("unique constraint violated")
	ErrNotFound        = errors.New("not found")
)
