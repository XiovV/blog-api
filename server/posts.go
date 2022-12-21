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
	user := s.getUserFromContext(c)

	var request struct {
		Title string `json:"title"`
		Body  string `json:"body"`
	}

	type response struct {
		ID    int    `json:"id"`
		Title string `json:"title"`
		Body  string `json:"body"`
	}

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

	res := response{
		ID:    newPost.ID,
		Title: newPost.Title,
		Body:  newPost.Body,
	}

	c.JSON(http.StatusCreated, res)
}

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

	s.successResponse(c, "post deleted successfully")
}

func (s *Server) getUserPostsHandler(c *gin.Context) {
	type response struct {
		ID    int    `json:"id"`
		Title string `json:"title"`
		Body  string `json:"body"`
	}

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

	posts, err := s.PostRepository.FindByUserID(user.ID, page, limit)
	if err != nil {
		s.Logger.Debug("couldn't find user posts", zap.Error(err), zap.String("username", username))
		c.JSON(http.StatusNotFound, gin.H{"error": "this user has no posts"})
		return
	}

	var res []response
	for _, post := range posts {
		res = append(res, response{
			ID:    post.ID,
			Title: post.Title,
			Body:  post.Body,
		})
	}

	c.JSON(http.StatusOK, gin.H{"posts": res})
}

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

	var request struct {
		Title *string `json:"title"`
		Body  *string `json:"body"`
	}

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

	err = s.PostRepository.UpdatePost(post)
	if err != nil {
		s.Logger.Error("couldn't update post", zap.Error(err))
		s.internalServerErrorResponse(c)
		return
	}

	s.successResponse(c, "post updated successfully")
}
