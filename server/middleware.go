package server

import (
	"errors"
	"github.com/XiovV/blog-api/pkg/repository"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"net/http"
)

func (s *Server) errorHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		err := c.Errors.Last()

		if err != nil {
			var errInvalidInput ErrInvalidInput

			switch {
			case errors.Is(err, repository.ErrUserAlreadyExists):
				c.JSON(http.StatusConflict, gin.H{"error": "a user with this username or email already exists"})
			case errors.Is(err, ErrInvalidJSON):
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
			case errors.As(err, &errInvalidInput):
				c.JSON(http.StatusBadRequest, gin.H{"error": errInvalidInput.Message})
			default:
				s.internalServerErrorResponse(c)
			}
		}

	}
}

func (s *Server) userAuth(c *gin.Context) {
	authToken, err := s.validateAuthorizationHeader(c)
	if err != nil {
		s.Logger.Debug("authorization header validation error", zap.Error(err))
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": err})
		return
	}

	token, err := validateAccessToken(authToken)
	if err != nil {
		s.Logger.Debug("invalid token", zap.Error(err))
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "invalid token"})
		return
	}

	userId := token.ID

	user, err := s.UserRepository.FindUserByID(userId)
	if err != nil {
		s.Logger.Debug("couldn't find user", zap.Error(err), zap.Int("userId", userId))
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	if !user.Active {
		s.Logger.Debug("user is inactive", zap.String("username", user.Username))
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "user inactive"})
		return
	}

	c.Set("user", user)

	c.Next()
}

func (s *Server) CORS() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}
