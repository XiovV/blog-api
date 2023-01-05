// Package server defines the blog api.
//
// The purpose of this application is to provide an application
//
//		Schemes: https
//		Host: localhost
//		BasePath: /v1
//		Version: 0.0.1
//
//		Consumes:
//		- application/json
//
//		Produces:
//		- application/json
//
//	    Security:
//	    - access_token:
//
//	    SecurityDefinitions:
//	    access_token:
//	         type: apiKey
//	         name: KEY
//	         in: header
//
// swagger:meta
package server

// swagger:model
type errorResponse struct {
	// Error response model
	Error string `json:"error"`
}

// swagger:model
type messageResponse struct {
	// Message response model
	Message string `json:"message"`
}

// swagger:model
type tokenPair struct {
	// user's access token
	AccessToken string `json:"access_token"`
	// user's refresh token
	RefreshToken string `json:"refresh_token"`
}
