package server

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"strconv"
)

const (
	MaxLimitValue = 100
	MinLimitValue = 1
	MinPageValue  = 1
)

func (s *Server) validatePageAndLimit(c *gin.Context) (int, int, error) {
	page, err := strconv.Atoi(c.Query("page"))
	if err != nil {
		return 0, 0, fmt.Errorf("page must be an integer")
	}

	limit, err := strconv.Atoi(c.Query("limit"))
	if err != nil {
		return 0, 0, fmt.Errorf("limit must be an integer")
	}

	if page < MinPageValue {
		return 0, 0, fmt.Errorf("page must be greater than 0")
	}

	if limit < MinLimitValue {
		return 0, 0, fmt.Errorf("limit must be greater than 0")
	}

	if limit > MaxLimitValue {
		return 0, 0, fmt.Errorf("maximum limit size is %d", MaxLimitValue)
	}

	return page, limit, nil
}
