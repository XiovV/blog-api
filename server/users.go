package server

import (
	"github.com/XiovV/blog-api/pkg/repository"
	"github.com/XiovV/blog-api/pkg/validator"
	"github.com/alexedwards/argon2id"
	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp/totp"
	"go.uber.org/zap"
	"net/http"
	"net/mail"
	"strconv"
	"strings"
	"time"
)

const (
	totpSecretLength = 32
	totpCodeLength   = 6
)

var argon2Params = argon2id.Params{
	Memory:      128 * 1024,
	Iterations:  10,
	Parallelism: 4,
	SaltLength:  16,
	KeyLength:   32,
}

type registerRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// @Summary Registers a user into the platform if the username and email haven't already been taken.
// @Tags user
// @Accept json
// @Produce json
// @Param request body registerRequest true "Register user body"
// @Success 200 {object} tokenPair
// @Failure 400 {object} errorResponse
// @Failure 409 {object} errorResponse "User with this username or email already exists"
// @Failure 500 {object} errorResponse
// @Router /users/register [post]
func (s *Server) registerUserHandler(c *gin.Context) {
	var request registerRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		s.Logger.Debug("json is invalid", zap.Error(err))
		c.Error(ErrInvalidJSON)
		return
	}

	request.Username = strings.TrimSpace(request.Username)
	request.Email = strings.TrimSpace(request.Email)

	v := validator.New()

	v.RequiredRange("username", request.Username, 3, 50)
	v.RequiredMin("password", request.Password, 8)

	ok, errors := v.IsValid()
	if !ok {
		s.Logger.Debug("input invalid", zap.Strings("err", errors))
		c.JSON(http.StatusBadRequest, gin.H{"error": errors})
		return
	}

	_, err := mail.ParseAddress(request.Email)
	if err != nil {
		s.Logger.Debug("email is invalid", zap.String("email", request.Email))
		s.badRequestResponse(c, "email is invalid")
		return
	}

	hash, err := argon2id.CreateHash(request.Password, &argon2Params)
	if err != nil {
		s.Logger.Error("couldn't hash password", zap.Error(err))
		s.internalServerErrorResponse(c)
		return
	}

	newUser := repository.User{Username: request.Username, Email: request.Email, Password: hash}
	id, err := s.UserRepository.InsertUser(newUser)
	if err != nil {
		s.Logger.Debug("couldn't insert user", zap.Error(err), zap.String("username", request.Username))
		c.Error(err)
		return
	}

	accessToken, err := generateAccessToken(id)
	if err != nil {
		s.Logger.Error("couldn't generate accessToken", zap.Error(err))
		s.internalServerErrorResponse(c)
		return
	}

	refreshToken, err := generateRefreshToken(id)
	if err != nil {
		s.Logger.Error("couldn't generate refreshToken", zap.Error(err))
		s.internalServerErrorResponse(c)
		return
	}

	go func() {
		err = s.Mailer.Send(request.Email, "welcome_user.tmpl", newUser)
		if err != nil {
			s.Logger.Error("couldn't send welcome email", zap.Error(err), zap.String("username", request.Username))
		}
	}()

	type registerResponse struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}

	c.JSON(http.StatusOK, registerResponse{accessToken, refreshToken})
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// @Summary Checks if the login credentials are correct and returns the access and refresh tokens.
// @Description If the user has 2FA enabled, 302 Found will be returned, in which case POST /users/login/mfa should be used to log the user in.
// @Tags user
// @Accept json
// @Produce json
// @Param request body loginRequest true "Login user body"
// @Success 200 {object} tokenPair
// @Failure 302 "User has 2FA enabled and needs to call POST /users/login/mfa."
// @Failure 400 {object} errorResponse
// @Failure 500 {object} errorResponse
// @Router /users/login [post]
func (s *Server) loginUserHandler(c *gin.Context) {
	var request loginRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		s.Logger.Debug("json is invalid", zap.Error(err))
		c.Error(ErrInvalidJSON)
		return
	}

	request.Username = strings.TrimSpace(request.Username)

	v := validator.New()

	v.RequiredRange("username", request.Username, 3, 50)
	v.RequiredMin("password", request.Password, 8)

	ok, errors := v.IsValid()
	if !ok {
		s.Logger.Debug("input invalid", zap.Strings("err", errors))
		c.JSON(http.StatusBadRequest, gin.H{"error": errors})
		return
	}

	user, err := s.UserRepository.FindUserByUsername(request.Username)
	if err != nil {
		s.Logger.Debug("couldn't find user", zap.Error(err), zap.String("username", request.Username))
		s.badRequestResponse(c, "incorrect username or password")
		return
	}

	ok, err = argon2id.ComparePasswordAndHash(request.Password, user.Password)
	if err != nil {
		s.Logger.Error("couldn't check hash", zap.Error(err), zap.String("username", request.Username))
		s.internalServerErrorResponse(c)
		return
	}

	if !ok {
		s.Logger.Debug("incorrect password", zap.String("username", request.Username))
		s.badRequestResponse(c, "incorrect username or password")
		return
	}

	if len(user.MFASecret) != 0 {
		s.Logger.Debug("user has 2fa enabled", zap.String("username", request.Username))
		c.Status(http.StatusFound)
		return
	}

	accessToken, err := generateAccessToken(user.ID)
	if err != nil {
		s.Logger.Error("couldn't generate accessToken", zap.Error(err))
		s.internalServerErrorResponse(c)
		return
	}

	refreshToken, err := generateRefreshToken(user.ID)
	if err != nil {
		s.Logger.Error("couldn't generate refreshToken", zap.Error(err))
		s.internalServerErrorResponse(c)
		return
	}

	type loginResponse struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}

	c.JSON(http.StatusOK, loginResponse{accessToken, refreshToken})
}

type mfaLoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	TOTP     string `json:"totp"`
}

// @Summary Checks if the login credentials and totp code are correct and returns the access and refresh tokens.
// @Description  Checks if the login credentials and totp code are correct and returns the access and refresh tokens. A 400 Bad Request status code and error message will be returned if the user doesn't have 2FA enabled, so only use this if the user has 2FA enabled on their account.
// @Tags user
// @Accept json
// @Produce json
// @Param request body mfaLoginRequest true "Login user body"
// @Success 200 {object} tokenPair
// @Failure 400 {object} errorResponse "Input is either invalid, or user doesn't have 2FA enabled."
// @Failure 500 {object} errorResponse
// @Router /users/login/mfa [post]
func (s *Server) loginUserMfaHandler(c *gin.Context) {
	var request mfaLoginRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		s.Logger.Debug("json is invalid", zap.Error(err))
		c.Error(ErrInvalidJSON)
		return
	}

	request.Username = strings.TrimSpace(request.Username)

	v := validator.New()

	v.RequiredMax("username", request.Username, 50)

	ok, errors := v.IsValid()
	if !ok {
		s.Logger.Debug("input invalid", zap.Strings("err", errors))
		c.JSON(http.StatusBadRequest, gin.H{"error": errors})
		return
	}

	user, err := s.UserRepository.FindUserByUsername(request.Username)
	if err != nil {
		s.Logger.Debug("couldn't find user", zap.Error(err))
		s.badRequestResponse(c, "incorrect username or password")
		return
	}

	ok, err = argon2id.ComparePasswordAndHash(request.Password, user.Password)
	if err != nil {
		s.Logger.Error("couldn't check hash", zap.Error(err))
		s.internalServerErrorResponse(c)
		return
	}

	if !ok {
		s.Logger.Debug("password is incorrect", zap.String("username", user.Username))
		s.badRequestResponse(c, "incorrect username or password")
		return
	}

	if len(user.MFASecret) == 0 {
		s.Logger.Debug("user doesn't have 2fa enabled", zap.String("username", request.Username))
		s.badRequestResponse(c, "this user doesn't have 2fa enabled")
		return
	}

	secret, err := s.decryptMfaSecret(user.MFASecret)
	if err != nil {
		s.Logger.Error("couldn't decrypt secret", zap.Error(err))
		s.internalServerErrorResponse(c)
		return
	}

	ok = totp.Validate(request.TOTP, string(secret))
	if !ok {
		s.Logger.Debug("invalid totp code", zap.String("totp", request.TOTP))
		c.Error(ErrInvalidInput{"invalid totp code"})
		return
	}

	accessToken, err := generateAccessToken(user.ID)
	if err != nil {
		s.Logger.Error("couldn't generate token", zap.Error(err))
		s.internalServerErrorResponse(c)
		return
	}

	refreshToken, err := generateRefreshToken(user.ID)
	if err != nil {
		s.Logger.Error("couldn't generate refreshToken", zap.Error(err))
		s.internalServerErrorResponse(c)
		return
	}

	type mfaLoginResponse struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}

	c.JSON(http.StatusOK, mfaLoginResponse{accessToken, refreshToken})
}

type recoveryLoginRequest struct {
	Username     string `json:"username"`
	Password     string `json:"password"`
	RecoveryCode string `json:"recovery_code"`
}

// @Summary Checks if the login credentials and recovery code are correct and returns the access and refresh tokens.
// @Tags user
// @Accept json
// @Produce json
// @Param request body recoveryLoginRequest true "Login user body"
// @Success 200 {object} tokenPair
// @Failure 400 {object} errorResponse "Input is either invalid, or the provided recovery code is incorrect."
// @Failure 500 {object} errorResponse
// @Router /users/login/recovery [post]
func (s *Server) loginUserRecoveryHandler(c *gin.Context) {
	var request recoveryLoginRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		s.Logger.Debug("json is invalid", zap.Error(err))
		c.Error(ErrInvalidJSON)
		return
	}

	request.Username = strings.TrimSpace(request.Username)

	v := validator.New()

	v.RequiredMax("username", request.Username, 50)

	ok, errors := v.IsValid()
	if !ok {
		s.Logger.Debug("input invalid", zap.Strings("err", errors))
		c.JSON(http.StatusBadRequest, gin.H{"error": errors})
		return
	}

	user, err := s.UserRepository.FindUserByUsername(request.Username)
	if err != nil {
		s.Logger.Debug("couldn't find user", zap.Error(err))
		s.badRequestResponse(c, "incorrect username or password")
		return
	}

	ok, err = argon2id.ComparePasswordAndHash(request.Password, user.Password)
	if err != nil {
		s.Logger.Error("couldn't check hash", zap.Error(err))
		s.internalServerErrorResponse(c)
		return
	}

	if !ok {
		s.Logger.Debug("password is incorrect", zap.String("username", user.Username))
		s.badRequestResponse(c, "incorrect username or password")
		return
	}

	recoveryCodes, err := s.UserRepository.GetUserRecoveryCodes(user.Username)
	if err != nil {
		s.Logger.Error("couldn't get recovery codes", zap.Error(err), zap.String("username", user.Username))
		s.internalServerErrorResponse(c)
		return
	}

	if len(recoveryCodes) == 0 {
		s.Logger.Debug("user doesn't have any recovery codes", zap.String("username", user.Username))
		s.badRequestResponse(c, "incorrect recovery code")
		return
	}

	ok = s.isRecoveryCodeValid(request.RecoveryCode, recoveryCodes)
	if !ok {
		s.Logger.Debug("incorrect recovery code", zap.String("code", request.RecoveryCode), zap.String("username", request.Username))
		s.badRequestResponse(c, "incorrect recovery code")
		return
	}

	recoveryCodesUpdated := removeRecoveryCode(recoveryCodes, request.RecoveryCode)

	err = s.UserRepository.SetRecoveryCodes(user.ID, recoveryCodesUpdated)
	if err != nil {
		s.Logger.Error("couldn't update recovery codes", zap.Error(err))
		s.internalServerErrorResponse(c)
		return
	}

	accessToken, err := generateAccessToken(user.ID)
	if err != nil {
		s.Logger.Error("couldn't generate token", zap.Error(err))
		s.internalServerErrorResponse(c)
		return
	}

	refreshToken, err := generateRefreshToken(user.ID)
	if err != nil {
		s.Logger.Error("couldn't generate refreshToken", zap.Error(err))
		s.internalServerErrorResponse(c)
		return
	}

	type recoveryLoginResponse struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}

	c.JSON(http.StatusOK, recoveryLoginResponse{accessToken, refreshToken})
}

type setupMfaHandlerResponse struct {
	Secret string `json:"secret"`
}

// @Summary Returns the secret used for generating TOTP codes.
// @Tags user
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Success 200 {object} setupMfaHandlerResponse
// @Failure 403 {object} errorResponse "The access token is invalid"
// @Failure 500 {object} errorResponse
// @Router /users/mfa [post]
func (s *Server) setupMfaHandler(c *gin.Context) {
	user := s.getUserFromContext(c)

	key, err := totp.Generate(totp.GenerateOpts{Issuer: "blog-api", AccountName: user.Username})
	if err != nil {
		s.Logger.Error("couldn't generate secret", zap.Error(err))
		s.internalServerErrorResponse(c)
		return
	}

	c.JSON(http.StatusOK, setupMfaHandlerResponse{key.Secret()})
}

type confirmMfaRequest struct {
	Secret string `json:"secret"`
	TOTP   string `json:"totp"`
}

type confirmMfaResponse struct {
	RecoveryCodes []string `json:"recovery_codes"`
}

// @Summary Checks if the provided TOTP code is correct and returns an array of recovery codes.
// @Tags user
// @Accept json
// @Produce json
// @Param request body confirmMfaRequest true "Login user body"
// @Security ApiKeyAuth
// @Success 200 {object} confirmMfaResponse
// @Failure 400 {object} errorResponse "Input is invalid"
// @Failure 403 {object} errorResponse "The access token is invalid"
// @Failure 500 {object} errorResponse
// @Router /users/mfa/confirm [post]
func (s *Server) confirmMfaHandler(c *gin.Context) {
	user := s.getUserFromContext(c)

	var request confirmMfaRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		s.Logger.Debug("json is invalid", zap.Error(err))
		c.Error(ErrInvalidJSON)
		return
	}

	v := validator.New()
	v.RequiredExact("secret", request.Secret, totpSecretLength)
	v.RequiredExact("totp", request.TOTP, totpCodeLength)

	ok, errors := v.IsValid()
	if !ok {
		s.Logger.Debug("input invalid", zap.Strings("err", errors))
		c.JSON(http.StatusBadRequest, gin.H{"error": errors})
		return
	}

	ok = totp.Validate(request.TOTP, request.Secret)
	if !ok {
		s.Logger.Debug("invalid totp code", zap.String("totp", request.TOTP))
		c.Error(ErrInvalidInput{"invalid totp code"})
		return
	}

	encryptedSecret := s.encryptMfaSecret([]byte(request.Secret))

	recoveryCodes := generateRecoveryCodes()

	err := s.UserRepository.InsertMfaSecret(user.ID, encryptedSecret, recoveryCodes)
	if err != nil {
		s.Logger.Error("couldn't insert secret", zap.Error(err))
		s.internalServerErrorResponse(c)
		return
	}

	c.JSON(http.StatusOK, confirmMfaResponse{recoveryCodes})
}

type personalPosts struct {
	ID    int    `json:"id"`
	Title string `json:"title"`
	Body  string `json:"body"`
}

type getPersonalPostsResponse struct {
	Posts []personalPosts `json:"posts"`
}

// @Summary Returns user's posts.
// @Tags user
// @Accept json
// @Produce json
// @Param page query int32 true "page"
// @Param limit query int32 true "limit"
// @Security ApiKeyAuth
// @Success 200 {object} getPersonalPostsResponse
// @Failure 400 {object} errorResponse "Input is invalid"
// @Failure 403 {object} errorResponse "The access token is invalid"
// @Failure 404 {object} errorResponse "User has no posts"
// @Failure 500 {object} errorResponse
// @Router /users/posts [get]
func (s *Server) getPersonalPostsHandler(c *gin.Context) {
	page, limit, err := s.validatePageAndLimit(c)
	if err != nil {
		s.Logger.Debug("invalid page and limit", zap.Error(err), zap.String("page", c.Query("page")), zap.String("limit", c.Query("limit")))
		c.Error(ErrInvalidInput{err.Error()})
		return
	}

	user := s.getUserFromContext(c)
	userPosts, err := s.PostRepository.FindByUserID(user.ID, page, limit)
	if err != nil {
		s.Logger.Debug("couldn't find user's posts", zap.String("username", user.Username))
		c.Error(err)
		return
	}

	var posts []personalPosts
	for _, post := range userPosts {
		posts = append(posts, personalPosts{
			ID:    post.ID,
			Title: post.Title,
			Body:  post.Body,
		})
	}

	c.JSON(http.StatusOK, getPersonalPostsResponse{posts})
}

// @Summary Returns user's posts.
// @Tags user
// @Accept json
// @Produce json
// @Param userId path int true "user id"
// @Security ApiKeyAuth
// @Success 200 "User deleted successfully"
// @Failure 400 {object} errorResponse "Input is invalid"
// @Failure 403 {object} errorResponse "The access token is invalid"
// @Failure 500 {object} errorResponse
// @Router /users/{userId} [delete]
func (s *Server) deleteUserHandler(c *gin.Context) {
	user := s.getUserFromContext(c)

	ok := s.enforcePermissions(c, user.Role, "user", "delete")
	if !ok {
		s.Logger.Debug("user has insufficient permissions", zap.String("username", user.Username), zap.String("role", user.Role))
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}

	userId, err := strconv.Atoi(c.Param("userId"))
	if err != nil {
		s.Logger.Debug("userId param not an integer", zap.Error(err), zap.String("userId", c.Param("userId")))
		s.badRequestResponse(c, "userId must be an integer")
		return
	}

	err = s.UserRepository.DeleteUserByID(userId)
	if err != nil {
		s.Logger.Error("couldn't delete user", zap.Error(err))
		s.internalServerErrorResponse(c)
		return
	}

	c.Status(http.StatusOK)
}

type refreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// @Summary Return a fresh pair of tokens.
// @Tags user
// @Accept json
// @Produce json
// @Param request body refreshTokenRequest true "Refresh token body"
// @Security ApiKeyAuth
// @Success 200 {object} tokenPair
// @Failure 400 {object} errorResponse "Input is invalid"
// @Failure 403 {object} errorResponse "The access token or refresh token is invalid."
// @Failure 500 {object} errorResponse
// @Router /users/token/refresh [post]
func (s *Server) refreshTokenHandler(c *gin.Context) {
	authToken, err := s.validateAuthorizationHeader(c)
	if err != nil {
		s.Logger.Debug("authorization header validation error", zap.Error(err))
		c.JSON(http.StatusForbidden, gin.H{"error": err})
		return
	}

	accessToken, err := parseToken(authToken)
	if err != nil {
		s.Logger.Debug("invalid accessToken", zap.Error(err))
		c.JSON(http.StatusForbidden, gin.H{"error": "invalid accessToken"})
		return
	}

	var request refreshTokenRequest
	if err = c.ShouldBindJSON(&request); err != nil {
		s.Logger.Debug("json is invalid", zap.Error(err))
		c.Error(ErrInvalidJSON)
		return
	}

	refreshToken, err := validateRefreshToken(request.RefreshToken)
	if err != nil {
		s.Logger.Debug("invalid refresh token", zap.Error(err))
		c.JSON(http.StatusForbidden, gin.H{"error": "invalid refresh token"})
		return
	}

	userId := accessToken.ID

	if userId != refreshToken.ID {
		s.Logger.Warn("refresh token used for the wrong user", zap.Int("expected", userId), zap.Int("got", refreshToken.ID))
		c.JSON(http.StatusForbidden, gin.H{"error": "refresh token used for the wrong user"})
		return
	}

	isTokenBlacklisted, err := s.UserRepository.IsRefreshTokenBlacklisted(userId, request.RefreshToken)
	if err != nil {
		s.Logger.Error("isTokenBlacklisted error", zap.Error(err))
		s.internalServerErrorResponse(c)
		return
	}

	if isTokenBlacklisted {
		s.Logger.Warn("accessToken is blacklisted", zap.Int("userId", userId))
		err = s.UserRepository.SetActiveState(userId, false)
		if err != nil {
			s.Logger.Error("couldn't disable user's account", zap.Error(err))
			s.internalServerErrorResponse(c)
			return
		}

		c.Status(http.StatusForbidden)
		return
	}

	newAccessToken, err := generateAccessToken(userId)
	if err != nil {
		s.Logger.Error("couldn't generate newAccessToken", zap.Error(err))
		s.internalServerErrorResponse(c)
		return
	}

	newRefreshToken, err := generateRefreshToken(userId)
	if err != nil {
		s.Logger.Error("couldn't generate newRefreshToken", zap.Error(err))
		s.internalServerErrorResponse(c)
		return
	}

	err = s.UserRepository.InsertRefreshToken(repository.RefreshToken{
		UserID: userId,
		Token:  request.RefreshToken,
	})

	if err != nil {
		s.Logger.Error("couldn't insert refresh accessToken", zap.Error(err))
		s.internalServerErrorResponse(c)
		return
	}

	type refreshTokenResponse struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}

	c.JSON(http.StatusOK, refreshTokenResponse{newAccessToken, newRefreshToken})
}

type createPasswordResetTokenRequest struct {
	Email string `json:"email"`
}

// @Summary Creates a password reset token and sends an email with password reset instructions.
// @Tags user
// @Accept json
// @Produce json
// @Param request body createPasswordResetTokenRequest true "Create password reset token body"
// @Success 200 {object} messageResponse
// @Failure 400 {object} errorResponse "Input is invalid"
// @Failure 500 {object} errorResponse
// @Router /users/password-reset [post]
func (s *Server) createPasswordResetToken(c *gin.Context) {
	var request createPasswordResetTokenRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		s.Logger.Debug("json is invalid", zap.Error(err))
		c.Error(ErrInvalidJSON)
		return
	}

	request.Email = strings.TrimSpace(request.Email)

	_, err := mail.ParseAddress(request.Email)
	if err != nil {
		s.Logger.Debug("email is invalid", zap.String("email", request.Email))
		s.badRequestResponse(c, "email is invalid")
		return
	}

	user, err := s.UserRepository.FindUserByEmail(request.Email)
	if err != nil {
		s.Logger.Debug("couldn't find user", zap.Error(err), zap.String("email", request.Email))
		c.Error(err)
		return
	}

	token := randomString(PasswordResetTokenLength)

	passwordResetToken := repository.PasswordResetToken{
		UserID: user.ID,
		Token:  token,
		Expiry: time.Now().Add(15 * time.Minute).Unix(),
	}

	err = s.UserRepository.InsertPasswordResetToken(passwordResetToken)
	if err != nil {
		s.Logger.Error("couldn't insert password reset token", zap.Error(err), zap.String("email", request.Email))
		c.Error(err)
		return
	}

	data := map[string]any{
		"passwordResetToken": token,
		"username":           user.Username,
	}

	go func() {
		err = s.Mailer.Send(request.Email, "password_reset.tmpl", data)
		if err != nil {
			s.Logger.Error("couldn't send email", zap.Error(err), zap.String("email", request.Email))
		}
	}()

	s.successResponse(c, "password reset email has been sent")
}

type resetUserPasswordRequest struct {
	Password string `json:"password"`
}

// @Summary Resets the user's password.
// @Tags user
// @Accept json
// @Produce json
// @Param request body resetUserPasswordRequest true "Reset password body"
// @Param token query string true "password reset token"
// @Success 200 {object} messageResponse
// @Failure 400 {object} errorResponse "Input is invalid"
// @Failure 403 {object} errorResponse "Password reset token is invalid"
// @Failure 500 {object} errorResponse
// @Router /users/password-reset [put]
func (s *Server) resetUserPasswordHandler(c *gin.Context) {
	var request resetUserPasswordRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		s.Logger.Debug("json is invalid", zap.Error(err))
		c.Error(ErrInvalidJSON)
		return
	}

	token := c.Query("token")

	v := validator.New()

	v.RequiredExact("token", token, PasswordResetTokenLength)
	v.RequiredMin("password", request.Password, 8)
	ok, errors := v.IsValid()
	if !ok {
		s.Logger.Debug("input invalid", zap.Strings("err", errors))
		c.JSON(http.StatusBadRequest, gin.H{"error": errors})
		return
	}

	passwordResetToken, err := s.UserRepository.GetPasswordResetToken(token)
	if err != nil {
		s.Logger.Debug("couldn't get password reset token", zap.Error(err), zap.String("token", token))
		c.JSON(http.StatusForbidden, gin.H{"error": "wrong reset password token"})
		return
	}

	if passwordResetToken.Expiry < time.Now().Unix() {
		c.JSON(http.StatusForbidden, gin.H{"error": "this token has expired"})
		err = s.UserRepository.DeletePasswordResetToken(token)
		if err != nil {
			s.Logger.Error("couldn't delete password reset token", zap.Error(err), zap.String("token", token))
		}
		return
	}

	hash, err := argon2id.CreateHash(request.Password, &argon2Params)
	if err != nil {
		s.Logger.Debug("couldn't hash password", zap.Error(err))
		s.internalServerErrorResponse(c)
		return
	}

	err = s.UserRepository.SetPassword(passwordResetToken.UserID, hash)
	if err != nil {
		s.Logger.Error("couldn't change user's password", zap.Error(err), zap.Int("userId", passwordResetToken.UserID))
		s.internalServerErrorResponse(c)
		return
	}

	err = s.UserRepository.DeleteAllPasswordResetTokensForUser(passwordResetToken.UserID)
	if err != nil {
		s.Logger.Error("couldn't delete all password reset tokens for user", zap.Error(err), zap.Int("userId", passwordResetToken.UserID))
		s.internalServerErrorResponse(c)
		return
	}

	s.successResponse(c, "password has been changed successfully")
}
