package repository

import "errors"

// Common repository errors
var (
	ErrNotFound     = errors.New("record not found")
	ErrDuplicate    = errors.New("record already exists")
	ErrInvalidInput = errors.New("invalid input")
)
