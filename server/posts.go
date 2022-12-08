package server

import (
	"github.com/XiovV/blog-api/pkg/repository"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"net/http"
	"strings"
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

	post := repository.Post{
		UserID: user.ID,
		Title:  request.Title,
		Body:   request.Body,
	}

	newPost, err := s.PostRepository.InsertPost(post)
	if err != nil {
		s.Logger.Error("couldn't insert post", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err})
		return
	}

	res := response{
		ID:    newPost.ID,
		Title: newPost.Title,
		Body:  newPost.Body,
	}

	c.JSON(http.StatusCreated, res)
}
