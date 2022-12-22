package repository

type Token struct {
	ID     int
	UserID int `db:"user_id"`
	Token  string
}

func (r *UserRepository) InsertRefreshToken(token Token) error {
	ctx, cancel := newBackgroundContext(DefaultQueryTimeout)
	defer cancel()

	_, err := r.db.ExecContext(ctx, "INSERT INTO token_blacklist (user_id, token) VALUES ($1, $2)", token.UserID, token.Token)
	return r.handleError(err)
}

func (r *UserRepository) IsRefreshTokenBlacklisted(userId int, token string) (bool, error) {
	var tok Token

	ctx, cancel := newBackgroundContext(DefaultQueryTimeout)
	defer cancel()

	err := r.db.GetContext(ctx, &tok, "SELECT user_id, token FROM token_blacklist WHERE user_id = $1 AND token = $2", userId, token)
	if err != nil {
		return false, r.handleError(err)
	}

	return true, nil
}
