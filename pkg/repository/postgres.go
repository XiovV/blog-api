package repository

import (
	"context"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"time"
)

const (
	MaxOpenConns        = 25
	MaxIdleConns        = 25
	MaxIdleTime         = "15m"
	DefaultQueryTimeout = 5
)

type Postgres struct {
	db *sqlx.DB
}

func NewPostgres(dsn string) (*sqlx.DB, error) {
	db, err := sqlx.Connect("postgres", dsn)
	if err != nil {
		return nil, err
	}

	db.SetMaxOpenConns(MaxOpenConns)
	db.SetMaxIdleConns(MaxIdleConns)

	duration, err := time.ParseDuration(MaxIdleTime)
	if err != nil {
		return nil, err
	}

	db.SetConnMaxIdleTime(duration)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = db.PingContext(ctx)
	if err != nil {
		return nil, err
	}

	return db, nil
}

func calculateOffset(page, limit int) int {
	return (page - 1) * limit
}

func newBackgroundContext(duration int) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
}
