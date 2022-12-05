package server

import (
	"github.com/XiovV/blog-api/pkg/validator"
	"github.com/gin-gonic/gin"
	"net/http"
)

func (s *Server) registerUserHandler(c *gin.Context) {
	var request struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		s.invalidJSONResponse(c)
		return
	}

	v := validator.New()

	v.RequiredMax("username", request.Username, 50)

	ok, errors := v.IsValid()
	if !ok {
		s.Logger.Warn("input invalid")
		c.JSON(http.StatusBadRequest, gin.H{"err": errors})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "okay"})
}
