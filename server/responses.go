package server

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

func (s *Server) successResponse(c *gin.Context, msg string) {
	c.JSON(http.StatusOK, gin.H{"message": msg})
}

func (s *Server) badRequestResponse(c *gin.Context, msg string) {
	c.JSON(http.StatusBadRequest, gin.H{"error": msg})
}

func (s *Server) invalidJSONResponse(c *gin.Context) {
	c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
}

func (s *Server) internalServerErrorResponse(c *gin.Context) {
	c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
}
