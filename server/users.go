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

func (s *Server) registerUserHandler(c *gin.Context) {
	// swagger:operation POST /users/register user registerUser
	//
	// Registers a user into the platform if the username and email haven't already been taken.
	// If everything has gone well, access and refresh tokens will be returned.
	//
	// ---
	// produces:
	// - application/json
	// parameters:
	//   - name: Body
	//     in: body
	//     schema:
	//       "$ref": "#/definitions/registerRequest"
	// responses:
	//   '200':
	//     description: User successfully registered.
	//     schema:
	//       "$ref": "#/definitions/tokenPair"
	//   '400':
	//     description: Input is invalid.
	//     schema:
	//       "$ref": "#/definitions/errorResponse"
	//   '409':
	//     description: A user with the provided username or email is already exists.
	//     schema:
	//       "$ref": "#/definitions/errorResponse"
	//   '500':
	//     description: Internal server error.
	//     schema:
	//       "$ref": "#/definitions/errorResponse"

	// swagger:model
	type registerRequest struct {
		// Username for this user
		// required: true
		// min length: 3
		// max length: 50
		Username string `json:"username"`
		// Email for this user
		// required: true
		Email string `json:"email"`
		// Password for this user
		// min length: 8
		Password string `json:"password"`
	}

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

	id, err := s.UserRepository.InsertUser(repository.User{Username: request.Username, Email: request.Email, Password: hash})
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

	type registerResponse struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}

	c.JSON(http.StatusOK, registerResponse{accessToken, refreshToken})
}

func (s *Server) loginUserHandler(c *gin.Context) {
	// swagger:operation POST /users/login user loginUser
	//
	// Checks if the login credentials are correct and returns the access and refresh tokens.
	// If the user has 2FA enabled, 302 Found will be returned, in which case POST /users/login/mfa should be used to log the user in.
	//
	// ---
	// produces:
	// - application/json
	// parameters:
	//   - name: Body
	//     in: body
	//     schema:
	//       "$ref": "#/definitions/loginRequest"
	// responses:
	//   '200':
	//     description: user successfully logged in
	//     schema:
	//       "$ref": "#/definitions/tokenPair"
	//   '302':
	//     description: User has 2FA enabled and needs to call POST /users/login/mfa. Only the status code is returned without a body.
	//   '400':
	//     description: Input is invalid.
	//     schema:
	//       "$ref": "#/definitions/errorResponse"
	//   '500':
	//     description: Internal server error
	//     schema:
	//       "$ref": "#/definitions/errorResponse"

	// swagger:model
	type loginRequest struct {
		// Username for this user
		// required: true
		// min length: 3
		// max length: 50
		Username string `json:"username"`
		// Password for this user
		// min length: 8
		Password string `json:"password"`
	}

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

func (s *Server) loginUserMfaHandler(c *gin.Context) {
	// swagger:operation POST /users/login/mfa user loginUserMfa
	//
	// Checks if the login credentials and totp code are correct and returns the access and refresh tokens.
	// A 400 Bad Request status code and error message will be returned if the user doesn't have 2FA enabled, so only use this if the user
	// has 2FA enabled on their account.
	//
	// ---
	// produces:
	// - application/json
	// parameters:
	//   - name: Body
	//     in: body
	//     schema:
	//       "$ref": "#/definitions/mfaLoginRequest"
	// responses:
	//   '200':
	//     description: User successfully logged in.
	//     schema:
	//       "$ref": "#/definitions/tokenPair"
	//   '400':
	//     description: Input is either invalid, or user doesn't have 2FA enabled.
	//     schema:
	//       "$ref": "#/definitions/errorResponse"
	//   '500':
	//     description: Internal server error.
	//     schema:
	//       "$ref": "#/definitions/errorResponse"

	// swagger:model
	type mfaLoginRequest struct {
		// Username for this user
		// required: true
		// min length: 3
		// max length: 50
		Username string `json:"username"`
		// Password for this user
		// min length: 8
		Password string `json:"password"`
		// TOTP code from an authenticator app
		// max length: 6
		TOTP string `json:"totp"`
	}

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

func (s *Server) loginUserRecoveryHandler(c *gin.Context) {
	// swagger:operation POST /users/login/recovery user loginUserRecovery
	//
	// Checks if the login credentials and recovery code are correct and returns the access and refresh tokens.
	//
	// ---
	// produces:
	// - application/json
	// parameters:
	//   - name: Body
	//     in: body
	//     schema:
	//       "$ref": "#/definitions/recoveryLoginRequest"
	// security:
	//   - access_token: []
	// responses:
	//   '200':
	//     description: User successfully logged in.
	//     schema:
	//       "$ref": "#/definitions/tokenPair"
	//   '400':
	//     description: Input is either invalid, or the provided recovery code is incorrect.
	//     schema:
	//       "$ref": "#/definitions/errorResponse"
	//   '500':
	//     description: Internal server error.
	//     schema:
	//       "$ref": "#/definitions/errorResponse"

	// swagger:model
	type recoveryLoginRequest struct {
		// Username for this user
		// required: true
		// min length: 3
		// max length: 50
		Username string `json:"username"`
		// Password for this user
		// min length: 8
		Password string `json:"password"`
		// Recovery code
		// max length: 7
		RecoveryCode string `json:"recovery_code"`
	}

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

func (s *Server) setupMfaHandler(c *gin.Context) {
	// swagger:operation POST /users/mfa user setupMfa
	//
	// Returns the secret used for generating TOTP codes.
	//
	// ---
	// produces:
	// - application/json
	// parameters:
	//   - name: access_token
	//     in: header
	//     required: true
	//     type: string
	// responses:
	//   '200':
	//     description: TOTP Secret is returned.
	//     schema:
	//       "$ref": "#/definitions/setupMfaHandlerResponse"
	//   '403':
	//     description: The access token is invalid.
	//     schema:
	//       "$ref": "#/definitions/errorResponse"
	//   '500':
	//     description: Internal server error.
	//     schema:
	//       "$ref": "#/definitions/errorResponse"

	user := s.getUserFromContext(c)

	key, err := totp.Generate(totp.GenerateOpts{Issuer: "blog-api", AccountName: user.Username})
	if err != nil {
		s.Logger.Error("couldn't generate secret", zap.Error(err))
		s.internalServerErrorResponse(c)
		return
	}

	//swagger:model
	type setupMfaHandlerResponse struct {
		// TOTP Secret
		Secret string `json:"secret"`
	}

	c.JSON(http.StatusOK, setupMfaHandlerResponse{key.Secret()})
}

func (s *Server) confirmMfaHandler(c *gin.Context) {
	// swagger:operation POST /users/mfa/confirm user confirmMfa
	//
	// Checks if the provided TOTP code is correct and returns an array of recovery codes.
	//
	// ---
	// produces:
	// - application/json
	// parameters:
	//   - name: access_token
	//     in: header
	//     required: true
	//     type: string
	//   - name: Body
	//     in: body
	//     required: true
	//     schema:
	//       "$ref": "#/definitions/confirmMfaRequest"
	// responses:
	//   '200':
	//     description: Recovery codes are returned.
	//     schema:
	//       "$ref": "#/definitions/confirmMfaResponse"
	//   '400':
	//     description: Input is invalid.
	//     schema:
	//       "$ref": "#/definitions/errorResponse"
	//   '403':
	//     description: The access token is invalid.
	//     schema:
	//       "$ref": "#/definitions/errorResponse"
	//   '500':
	//     description: Internal server error.
	//     schema:
	//       "$ref": "#/definitions/errorResponse"

	user := s.getUserFromContext(c)

	//swagger:model
	type confirmMfaRequest struct {
		Secret string `json:"secret"`
		TOTP   string `json:"totp"`
	}

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

	//swagger:model
	type confirmMfaResponse struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}

	c.JSON(http.StatusOK, confirmMfaResponse{recoveryCodes})
}

func (s *Server) getPersonalPostsHandler(c *gin.Context) {
	// swagger:operation GET /users/posts user getPersonalPosts
	//
	// Returns user's posts.
	//
	// ---
	// produces:
	// - application/json
	// parameters:
	//   - name: access_token
	//     in: header
	//     required: true
	//     type: string
	//   - name: page
	//     in: query
	//     required: false
	//     type: integer
	//     format: int32
	//   - name: limit
	//     in: query
	//     required: false
	//     type: integer
	//     format: int32
	// responses:
	//   '200':
	//     description: User's posts are returned.
	//     schema:
	//       "$ref": "#/definitions/getPersonalPostsResponse"
	//   '403':
	//     description: The access token is invalid.
	//     schema:
	//       "$ref": "#/definitions/errorResponse"
	//   '404':
	//     description: User doesn't have any posts.
	//     schema:
	//       "$ref": "#/definitions/errorResponse"
	//   '500':
	//     description: Internal server error.
	//     schema:
	//       "$ref": "#/definitions/errorResponse"

	type personalPosts struct {
		ID    int    `json:"id"`
		Title string `json:"title"`
		Body  string `json:"body"`
	}

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
		c.JSON(http.StatusNotFound, gin.H{"error": "user doesn't have any posts"})
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

	//swagger:model
	type getPersonalPostsResponse struct {
		Posts []personalPosts `json:"posts"`
	}

	c.JSON(http.StatusOK, getPersonalPostsResponse{posts})
}

func (s *Server) deleteUserHandler(c *gin.Context) {
	// swagger:operation DELETE /users user deleteUser
	//
	// Deletes a user.
	//
	// ---
	// produces:
	// - application/json
	// parameters:
	//   - name: access_token
	//     in: header
	//     required: true
	//     type: string
	//   - name: id
	//     description: id of the user
	//     in: query
	//     required: false
	//     type: integer
	//     format: int32
	// responses:
	//   '200':
	//     description: User deleted successfully.
	//   '403':
	//     description: The access token is invalid or the permissions are insufficient to perform this action.
	//     schema:
	//       "$ref": "#/definitions/errorResponse"
	//   '500':
	//     description: Internal server error.
	//     schema:
	//       "$ref": "#/definitions/errorResponse"

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

func (s *Server) refreshTokenHandler(c *gin.Context) {
	// swagger:operation POST /users/token/refresh user refreshTokens
	//
	// Refreshes the user's tokens.
	//
	// ---
	// produces:
	// - application/json
	// parameters:
	//   - name: access_token
	//     in: header
	//     required: true
	//     type: string
	//   - name: Body
	//     in: body
	//     required: true
	//     schema:
	//       "$ref": "#/definitions/refreshTokenRequest"
	// responses:
	//   '200':
	//     description: New access token and refresh tokens are returned.
	//     schema:
	//       "$ref": "#/definitions/tokenPair"
	//   '400':
	//     description: Input is invalid.
	//     schema:
	//       "$ref": "#/definitions/errorResponse"
	//   '403':
	//     description: The access token or refresh token is invalid.
	//     schema:
	//       "$ref": "#/definitions/errorResponse"
	//   '500':
	//     description: Internal server error.
	//     schema:
	//       "$ref": "#/definitions/errorResponse"

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

	// swagger:model
	type refreshTokenRequest struct {
		// User's refresh token
		RefreshToken string `json:"refresh_token"`
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

	err = s.UserRepository.InsertRefreshToken(repository.Token{
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
