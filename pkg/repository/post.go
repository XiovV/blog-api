package repository

import (
	"errors"
	"github.com/jmoiron/sqlx"
)

var (
	ErrPostNotFound = errors.New("post not found")
)

type PostRepository struct {
	db *sqlx.DB
}

type Post struct {
	ID     int
	UserID int `db:"user_id"`
	Title  string
	Body   string
}

func NewPostRepository(db *sqlx.DB) *PostRepository {
	return &PostRepository{db: db}
}

func (r *PostRepository) handleError(err error) error {
	err = handleError(err)

	switch {
	case errors.Is(err, ErrNotFound):
		return ErrPostNotFound
	default:
		return err
	}
}

func (r *PostRepository) InsertPost(post Post) (Post, error) {
	var newPost Post

	ctx, cancel := newBackgroundContext(DefaultQueryTimeout)
	defer cancel()

	err := r.db.GetContext(ctx, &newPost, "INSERT INTO post (user_id, title, body) VALUES ($1, $2, $3) RETURNING *;", post.UserID, post.Title, post.Body)
	if err != nil {
		return Post{}, r.handleError(err)
	}

	return newPost, nil
}

func (r *PostRepository) FindPostByPostID(postId int) (Post, error) {
	var post Post

	ctx, cancel := newBackgroundContext(DefaultQueryTimeout)
	defer cancel()

	err := r.db.GetContext(ctx, &post, "SELECT * FROM post WHERE id = $1", postId)
	if err != nil {
		return Post{}, r.handleError(err)
	}

	return post, nil
}

func (r *PostRepository) DeletePostByPostID(postId int) error {
	ctx, cancel := newBackgroundContext(DefaultQueryTimeout)
	defer cancel()

	_, err := r.db.ExecContext(ctx, "DELETE FROM post WHERE id = $1", postId)
	return r.handleError(err)
}

func (r *PostRepository) UpdatePost(post Post) (Post, error) {
	var updatedPost Post

	ctx, cancel := newBackgroundContext(DefaultQueryTimeout)
	defer cancel()

	err := r.db.GetContext(ctx, &updatedPost, "UPDATE post SET title = $1, body = $2 WHERE id = $3 RETURNING *", post.Title, post.Body, post.ID)
	if err != nil {
		return Post{}, r.handleError(err)
	}

	return updatedPost, nil
}

func (r *PostRepository) FindByUserID(userId, page, limit int) ([]Post, error) {
	var posts []Post

	ctx, cancel := newBackgroundContext(DefaultQueryTimeout)
	defer cancel()

	err := r.db.SelectContext(ctx, &posts, "SELECT * FROM post WHERE user_id = $1 LIMIT $2 OFFSET $3", userId, limit, calculateOffset(page, limit))
	if err != nil {
		return nil, r.handleError(err)
	}

	return posts, nil
}
