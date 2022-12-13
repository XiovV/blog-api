package repository

import "github.com/jmoiron/sqlx"

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

func (r *PostRepository) InsertPost(post Post) (Post, error) {
	var newPost Post

	ctx, cancel := newBackgroundContext(DefaultQueryTimeout)
	defer cancel()

	err := r.db.GetContext(ctx, &newPost, "INSERT INTO post (user_id, title, body) VALUES ($1, $2, $3) RETURNING *;", post.UserID, post.Title, post.Body)
	if err != nil {
		return Post{}, err
	}

	return newPost, nil
}

func (r *PostRepository) FindPostByPostID(postId int) (Post, error) {
	var post Post

	ctx, cancel := newBackgroundContext(DefaultQueryTimeout)
	defer cancel()

	err := r.db.GetContext(ctx, &post, "SELECT * FROM post WHERE id = $1", postId)
	if err != nil {
		return Post{}, err
	}

	return post, nil
}

func (r *PostRepository) DeletePostByPostID(postId int) error {
	ctx, cancel := newBackgroundContext(DefaultQueryTimeout)
	defer cancel()

	_, err := r.db.ExecContext(ctx, "DELETE FROM post WHERE id = $1", postId)
	return err
}

func (r *PostRepository) UpdatePost(post Post) error {
	ctx, cancel := newBackgroundContext(DefaultQueryTimeout)
	defer cancel()

	_, err := r.db.ExecContext(ctx, "UPDATE post SET title = $1, body = $2 WHERE id = $3", post.Title, post.Body, post.ID)
	if err != nil {
		return err
	}

	return nil
}

func (r *PostRepository) FindByUserID(userId, page, limit int) ([]Post, error) {
	var posts []Post

	ctx, cancel := newBackgroundContext(DefaultQueryTimeout)
	defer cancel()

	err := r.db.SelectContext(ctx, &posts, "SELECT * FROM post WHERE user_id = $1 LIMIT $2 OFFSET $3", userId, limit, calculateOffset(page, limit))
	if err != nil {
		return nil, err
	}

	return posts, nil
}
