// Package server defines the blog api.
//
// The purpose of this application is to provide an application
//
//	Schemes: https
//	Host: localhost
//	BasePath: /v1
//	Version: 0.0.1
//
//	Consumes:
//	- application/json
//
//	Produces:
//	- application/json
//
// swagger:meta
package server

// swagger:model
type errorResponse struct {
	// Error response model
	Error string `json:"error"`
}
