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

type createPostRequest struct {
	Title string `json:"title"`
	Body  string `json:"body"`
}

type createPostResponse struct {
	ID    int    `json:"id"`
	Title string `json:"title"`
	Body  string `json:"body"`
}

// @Summary Creates a post
// @Tags post
// @Accept json
// @Produce json
// @Param request body createPostRequest true "Create post body"
// @Security ApiKeyAuth
// @Success 200 {object} createPostResponse
// @Failure 400 {object} errorResponse "Input is invalid"
// @Failure 403 {object} errorResponse "The access token is invalid"
// @Failure 500 {object} errorResponse
// @Router /posts/ [post]
func (s *Server) createPostHandler(c *gin.Context) {
	user := s.getUserFromContext(c)

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

	response := createPostResponse{
		ID:    newPost.ID,
		Title: newPost.Title,
		Body:  newPost.Body,
	}

	c.JSON(http.StatusCreated, response)
}

// TODO: add author info here
type getPostResponse struct {
	ID    int    `json:"id"`
	Title string `json:"title"`
	Body  string `json:"body"`
}

// @Summary Gets a post
// @Tags post
// @Accept json
// @Produce json
// @Param postId path int true "post id"
// @Security ApiKeyAuth
// @Success 200 {object} getPostResponse
// @Failure 400 {object} errorResponse "Input is invalid"
// @Failure 403 {object} errorResponse "The access token is invalid"
// @Failure 404 {object} errorResponse "A post with the provided id doesn't exist"
// @Failure 500 {object} errorResponse
// @Router /posts/{postId} [get]
func (s *Server) getPostHandler(c *gin.Context) {
	postId, err := strconv.Atoi(c.Param("postId"))
	if err != nil {
		s.Logger.Debug("post id not an integer", zap.String("postId", c.Param("postId")))
		s.badRequestResponse(c, "post id must be an integer")
		return
	}

	post, err := s.PostRepository.FindPostByPostID(postId)
	if err != nil {
		s.Logger.Debug("post could not be found", zap.Error(err), zap.Int("postId", postId))
		c.Error(err)
		return
	}

	c.JSON(http.StatusOK, getPostResponse{
		ID:    post.ID,
		Title: post.Title,
		Body:  post.Body,
	})
}

// @Summary Deletes a post
// @Tags post
// @Accept json
// @Produce json
// @Param postId path int true "post id"
// @Security ApiKeyAuth
// @Success 200 "Post deleted successfully"
// @Failure 400 {object} errorResponse "Input is invalid"
// @Failure 403 {object} errorResponse "The access token is invalid or the permissions for performing this action are insufficient"
// @Failure 404 {object} errorResponse "A post with the provided id doesn't exist"
// @Failure 500 {object} errorResponse
// @Router /posts/{postId} [delete]
func (s *Server) deletePostHandler(c *gin.Context) {
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
		c.Error(err)
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

// @Summary Deletes a post
// @Tags post
// @Accept json
// @Produce json
// @Param username path string true "username"
// @Param page query int32 true "page"
// @Param limit query int32 true "limit"
// @Security ApiKeyAuth
// @Success 200 {object} getPersonalPostsResponse
// @Failure 400 {object} errorResponse "Input is invalid"
// @Failure 403 {object} errorResponse "The access token is invalid or the permissions for performing this action are insufficient"
// @Failure 404 {object} errorResponse "User has no posts"
// @Failure 500 {object} errorResponse
// @Router /posts/user/{username} [get]
func (s *Server) getUserPostsHandler(c *gin.Context) {
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
		c.Error(err)
		return
	}

	userPosts, err := s.PostRepository.FindByUserID(user.ID, page, limit)
	if err != nil {
		s.Logger.Debug("couldn't find user posts", zap.Error(err), zap.String("username", username))
		c.Error(err)
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

type updatePostRequest struct {
	Title *string `json:"title"`
	Body  *string `json:"body"`
}

type updatePostResponse struct {
	ID    int    `json:"id"`
	Title string `json:"title"`
	Body  string `json:"body"`
}

// @Summary Edits a post
// @Tags post
// @Accept json
// @Produce json
// @Param postId path int true "post id"
// @Param request body updatePostRequest true "Edit post body"
// @Security ApiKeyAuth
// @Success 200 {object} updatePostResponse
// @Failure 400 {object} errorResponse "Input is invalid"
// @Failure 403 {object} errorResponse "The access token is invalid or the permissions for performing this action are insufficient"
// @Failure 404 {object} errorResponse "User has no posts"
// @Failure 500 {object} errorResponse
// @Router /posts/{postId} [put]
func (s *Server) editPostHandler(c *gin.Context) {
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
		c.Error(err)
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

	response := updatePostResponse{
		ID:    updatedPost.ID,
		Title: updatedPost.Title,
		Body:  updatedPost.Body,
	}

	c.JSON(http.StatusOK, response)
}
