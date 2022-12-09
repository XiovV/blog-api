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

	err := r.db.Get(&newPost, "INSERT INTO post (user_id, title, body) VALUES ($1, $2, $3) RETURNING *;", post.UserID, post.Title, post.Body)
	if err != nil {
		return Post{}, err
	}

	return newPost, nil
}

func (r *PostRepository) FindPostByPostID(postId int) (Post, error) {
	var post Post

	err := r.db.Get(&post, "SELECT * FROM post WHERE id = $1", postId)
	if err != nil {
		return Post{}, err
	}

	return post, nil
}

func (r *PostRepository) DeletePostByPostID(postId int) error {
	_, err := r.db.Exec("DELETE FROM post WHERE id = $1", postId)
	return err
}
