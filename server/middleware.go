package server

import (
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"net/http"
	"strings"
)

func (s *Server) userAuth(c *gin.Context) {
	tokenHeader := c.GetHeader("Authorization")

	if len(tokenHeader) == 0 {
		s.Logger.Debug("did not receive Authorization header")
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "did not receive Authorization header"})
		return
	}

	authorizationHeaderSplit := strings.Split(tokenHeader, " ")
	if len(authorizationHeaderSplit) != 2 {
		s.Logger.Debug("wrong Authorization header format")
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "wrong Authorization header format"})
		return
	}

	if authorizationHeaderSplit[0] != "Bearer" {
		s.Logger.Debug("wrong Authorization header format, missing keyword Bearer")
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "wrong Authorization header format"})
		return
	}

	authToken := authorizationHeaderSplit[1]

	token, err := validateToken(authToken)
	if err != nil {
		s.Logger.Debug("invalid token", zap.Error(err))
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "invalid token"})
		return
	}

	userId := getClaimInt(token, "ID")

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
