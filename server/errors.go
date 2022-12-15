package server

import "errors"

var (
	ErrInvalidJSON = errors.New("json is invalid")
)

type ErrInvalidInput struct {
	Message string
}

func (e ErrInvalidInput) Error() string {
	return e.Message
}
