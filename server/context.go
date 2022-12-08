package server

import (
	"github.com/XiovV/blog-api/pkg/repository"
	"github.com/gin-gonic/gin"
	"net/http"
)

func (s *Server) getUserFromContext(c *gin.Context) repository.User {
	userCtx, exists := c.Get("user")
	if !exists {
		s.Logger.Error("user not found in context")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return repository.User{}
	}

	return userCtx.(repository.User)
}
