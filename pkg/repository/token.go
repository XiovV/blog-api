package repository

type RefreshToken struct {
	ID     int
	UserID int `db:"user_id"`
	Token  string
}

func (r *UserRepository) InsertRefreshToken(token RefreshToken) error {
	ctx, cancel := newBackgroundContext(DefaultQueryTimeout)
	defer cancel()

	_, err := r.db.ExecContext(ctx, "INSERT INTO token_blacklist (user_id, token) VALUES ($1, $2)", token.UserID, token.Token)
	return r.handleError(err)
}

func (r *UserRepository) IsRefreshTokenBlacklisted(userId int, token string) (bool, error) {
	var tok RefreshToken

	ctx, cancel := newBackgroundContext(DefaultQueryTimeout)
	defer cancel()

	err := r.db.GetContext(ctx, &tok, "SELECT user_id, token FROM token_blacklist WHERE user_id = $1 AND token = $2", userId, token)
	if err != nil {
		return false, r.handleError(err)
	}

	return true, nil
}

type PasswordResetToken struct {
	ID     int
	UserID int `db:"user_id"`
	Token  string
	Expiry int64
}

func (r *UserRepository) InsertPasswordResetToken(token PasswordResetToken) error {
	ctx, cancel := newBackgroundContext(DefaultQueryTimeout)
	defer cancel()

	_, err := r.db.ExecContext(ctx, "INSERT INTO password_reset_token (user_id, token, expiry) VALUES ($1, $2, $3)", token.UserID, token.Token, token.Expiry)
	return r.handleError(err)
}

func (r *UserRepository) GetPasswordResetToken(token string) (PasswordResetToken, error) {
	var tok PasswordResetToken

	ctx, cancel := newBackgroundContext(DefaultQueryTimeout)
	defer cancel()

	err := r.db.GetContext(ctx, &tok, "SELECT id, user_id, token, expiry FROM password_reset_token WHERE token = $1", token)
	if err != nil {
		return PasswordResetToken{}, r.handleError(err)
	}

	return tok, nil
}

func (r *UserRepository) DeleteAllPasswordResetTokensForUser(userId int) error {
	ctx, cancel := newBackgroundContext(DefaultQueryTimeout)
	defer cancel()

	_, err := r.db.ExecContext(ctx, "DELETE FROM password_reset_token WHERE user_id = $1", userId)
	return r.handleError(err)
}

func (r *UserRepository) DeletePasswordResetToken(token string) error {
	ctx, cancel := newBackgroundContext(DefaultQueryTimeout)
	defer cancel()

	_, err := r.db.ExecContext(ctx, "DELETE FROM password_reset_token WHERE token = $1", token)
	return r.handleError(err)
}
