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
	maxTitleLenght = 256
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
		s.invalidJSONResponse(c)
		return
	}

	request.Title = strings.TrimSpace(request.Title)

	v := validator.New()
	v.RequiredMax("title", request.Title, maxTitleLenght)

	ok, errors := v.IsValid()
	if !ok {
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

func (s *Server) deletePostHandler(c *gin.Context) {
	user := s.getUserFromContext(c)

	postId, err := strconv.Atoi(c.Param("postId"))
	if err != nil {
		s.badRequestResponse(c, "post id must be an integer")
		return
	}

	post, err := s.PostRepository.FindPostByPostID(postId)
	if err != nil {
		s.Logger.Error("couldn't find post", zap.Error(err))
		c.JSON(http.StatusNotFound, gin.H{"error": "the post could not be found"})
		return
	}

	if post.UserID != user.ID {
		ok, err := s.CasbinEnforcer.Enforce(user.Role, "post", "delete")
		if err != nil {
			s.Logger.Error("error enforcing rules", zap.Error(err))
			s.internalServerErrorResponse(c)
			return
		}

		if !ok {
			c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
			return
		}
	}

	err = s.PostRepository.DeletePostByPostID(postId)
	if err != nil {
		s.Logger.Error("couldn't delete post", zap.Error(err))
		s.internalServerErrorResponse(c)
		return
	}

	s.successResponse(c, "post deleted successfully")
}
