package server

import (
	"github.com/XiovV/blog-api/pkg/repository"
	"github.com/XiovV/blog-api/pkg/validator"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"net/http"
	"strconv"
	"strings"
)

const (
	maxTitleLength = 256
)

func (s *Server) createPostHandler(c *gin.Context) {
	// swagger:operation POST /posts post createPost
	//
	// Creates a post and returns the created post.
	//
	// ---
	// produces:
	// - application/json
	// parameters:
	//   - name: access_token
	//     in: header
	//     required: true
	//     type: string
	//   - name: post id
	//     in: query
	//     required: false
	//     type: integer
	//     format: int32
	// responses:
	//   '200':
	//     description: The requested post is returned.
	//     schema:
	//       "$ref": "#/definitions/createPostResponse"
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
	type createPostRequest struct {
		Title string `json:"title"`
		Body  string `json:"body"`
	}

	var request createPostRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		s.Logger.Debug("json is invalid", zap.Error(err))
		c.Error(ErrInvalidJSON)
		return
	}

	request.Title = strings.TrimSpace(request.Title)

	v := validator.New()
	v.RequiredMax("title", request.Title, maxTitleLength)

	ok, errors := v.IsValid()
	if !ok {
		s.Logger.Debug("input is invalid", zap.Strings("error", errors))
		c.JSON(http.StatusBadRequest, gin.H{"error": errors})
		return
	}

	post := repository.Post{
		UserID: user.ID,
		Title:  request.Title,
		Body:   request.Body,
	}

	newPost, err := s.PostRepository.InsertPost(post)
	if err != nil {
		s.Logger.Error("couldn't insert post", zap.Error(err))
		s.internalServerErrorResponse(c)
		return
	}

	//swagger:model
	type createPostResponse struct {
		ID    int    `json:"id"`
		Title string `json:"title"`
		Body  string `json:"body"`
	}

	response := createPostResponse{
		ID:    newPost.ID,
		Title: newPost.Title,
		Body:  newPost.Body,
	}

	c.JSON(http.StatusCreated, response)
}

func (s *Server) getPostHandler(c *gin.Context) {
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

	postId, err := strconv.Atoi(c.Param("postId"))
	if err != nil {
		s.Logger.Debug("post id not an integer", zap.String("postId", c.Param("postId")))
		s.badRequestResponse(c, "post id must be an integer")
		return
	}

	post, err := s.PostRepository.FindPostByPostID(postId)
	if err != nil {
		s.Logger.Debug("post could not be found", zap.Error(err), zap.Int("postId", postId))
		c.JSON(http.StatusNotFound, gin.H{"error": "the post could be found"})
		return
	}

	//TODO: add author info here
	type response struct {
		ID    int    `json:"id"`
		Title string `json:"title"`
		Body  string `json:"body"`
	}

	c.JSON(http.StatusOK, response{
		ID:    post.ID,
		Title: post.Title,
		Body:  post.Body,
	})
}

func (s *Server) deletePostHandler(c *gin.Context) {
	// swagger:operation DELETE /posts post deletePost
	//
	// Deletes a post.
	//
	// ---
	// produces:
	// - application/json
	// parameters:
	//   - name: access_token
	//     in: header
	//     required: true
	//     type: string
	//   - name: post id
	//     in: query
	//     required: false
	//     type: integer
	//     format: int32
	// responses:
	//   '200':
	//     description: Post deleted successfully.
	//   '403':
	//     description: The access token is invalid or the permissions are insufficient to perform this action.
	//     schema:
	//       "$ref": "#/definitions/errorResponse"
	//   '404':
	//     description: The post could not be found.
	//     schema:
	//       "$ref": "#/definitions/errorResponse"
	//   '500':
	//     description: Internal server error.
	//     schema:
	//       "$ref": "#/definitions/errorResponse"

	user := s.getUserFromContext(c)

	postId, err := strconv.Atoi(c.Param("postId"))
	if err != nil {
		s.Logger.Debug("post id not an integer", zap.String("postId", c.Param("postId")))
		s.badRequestResponse(c, "post id must be an integer")
		return
	}

	post, err := s.PostRepository.FindPostByPostID(postId)
	if err != nil {
		s.Logger.Debug("post could not be found", zap.Error(err), zap.Int("postId", postId))
		c.JSON(http.StatusNotFound, gin.H{"error": "the post could not be found"})
		return
	}

	if post.UserID != user.ID {
		ok := s.enforcePermissions(c, user.Role, "post", "delete")
		if !ok {
			s.Logger.Debug("user has insufficient permissions", zap.String("username", user.Username), zap.String("role", user.Role))
			c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
			return
		}
	}

	err = s.PostRepository.DeletePostByPostID(postId)
	if err != nil {
		s.Logger.Error("couldn't delete post", zap.Error(err), zap.Int("postId", postId))
		s.internalServerErrorResponse(c)
		return
	}

	c.Status(http.StatusOK)
}

func (s *Server) getUserPostsHandler(c *gin.Context) {
	// swagger:operation GET /posts/user/{username} post getUserPosts
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
	//   - name: username
	//     in: path
	//     required: true
	//     type: integer
	//     format: int64
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

	page, limit, err := s.validatePageAndLimit(c)
	if err != nil {
		s.Logger.Debug("invalid page and limit", zap.Error(err), zap.String("page", c.Query("page")), zap.String("limit", c.Query("limit")))
		s.badRequestResponse(c, err.Error())
		return
	}

	username := c.Param("username")

	user, err := s.UserRepository.FindUserByUsername(username)
	if err != nil {
		s.Logger.Debug("couldn't find user", zap.Error(err), zap.String("username", username))
		c.JSON(http.StatusNotFound, gin.H{"error": "couldn't find user"})
		return
	}

	userPosts, err := s.PostRepository.FindByUserID(user.ID, page, limit)
	if err != nil {
		s.Logger.Debug("couldn't find user posts", zap.Error(err), zap.String("username", username))
		c.JSON(http.StatusNotFound, gin.H{"error": "this user has no posts"})
		return
	}

	type personalPosts struct {
		ID    int    `json:"id"`
		Title string `json:"title"`
		Body  string `json:"body"`
	}

	var posts []personalPosts
	for _, post := range userPosts {
		posts = append(posts, personalPosts{
			ID:    post.ID,
			Title: post.Title,
			Body:  post.Body,
		})
	}

	type getPersonalPostsResponse struct {
		Posts []personalPosts
	}

	c.JSON(http.StatusOK, getPersonalPostsResponse{posts})
}

func (s *Server) editPostHandler(c *gin.Context) {
	// swagger:operation PUT /posts/{postId} post editPost
	//
	// Edits a user.
	//
	// ---
	// produces:
	// - application/json
	// parameters:
	//   - name: access_token
	//     in: header
	//     required: true
	//     type: string
	//   - name: postId
	//     in: path
	//     required: true
	//     type: integer
	//     format: int64
	//   - name: Body
	//     in: body
	//     required: true
	//     schema:
	//       "$ref": "#/definitions/updatePostRequest"
	// responses:
	//   '200':
	//     description: Post updated successfully.
	//     schema:
	//       "$ref": "#/definitions/updatePostResponse"
	//   '403':
	//     description: The access token is invalid or the permissions are insufficient to perform this action.
	//     schema:
	//       "$ref": "#/definitions/errorResponse"
	//   '404':
	//     description: Post not found.
	//     schema:
	//       "$ref": "#/definitions/errorResponse"
	//   '500':
	//     description: Internal server error.
	//     schema:
	//       "$ref": "#/definitions/errorResponse"

	user := s.getUserFromContext(c)

	postId, err := strconv.Atoi(c.Param("postId"))
	if err != nil {
		s.Logger.Debug("postId not an integer", zap.Error(err))
		s.badRequestResponse(c, "postId must be an integer")
		return
	}

	post, err := s.PostRepository.FindPostByPostID(postId)
	if err != nil {
		s.Logger.Debug("couldn't find post", zap.Int("postId", postId))
		c.JSON(http.StatusNotFound, gin.H{"error": "post could not be found"})
		return
	}

	if post.UserID != user.ID {
		ok := s.enforcePermissions(c, user.Role, "post", "write")
		if !ok {
			s.Logger.Debug("user has insufficient permissions", zap.String("username", user.Username))
			c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
			return
		}
	}

	// swagger:model
	type updatePostRequest struct {
		Title *string `json:"title"`
		Body  *string `json:"body"`
	}

	var request updatePostRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		s.Logger.Debug("json is invalid", zap.Error(err))
		c.Error(ErrInvalidJSON)
		return
	}

	if request.Title != nil {
		post.Title = *request.Title
	}

	if request.Body != nil {
		post.Body = *request.Body
	}

	post.Title = strings.TrimSpace(post.Title)

	v := validator.New()
	v.RequiredMax("title", post.Title, maxTitleLength)

	ok, errors := v.IsValid()
	if !ok {
		s.Logger.Debug("input is invalid", zap.Strings("error", errors))
		c.JSON(http.StatusBadRequest, gin.H{"error": errors})
		return
	}

	updatedPost, err := s.PostRepository.UpdatePost(post)
	if err != nil {
		s.Logger.Error("couldn't update post", zap.Error(err))
		s.internalServerErrorResponse(c)
		return
	}

	//swagger:model
	type updatePostResponse struct {
		ID    int    `json:"id"`
		Title string `json:"title"`
		Body  string `json:"body"`
	}

	response := updatePostResponse{
		ID:    updatedPost.ID,
		Title: updatedPost.Title,
		Body:  updatedPost.Body,
	}

	c.JSON(http.StatusOK, response)
}
