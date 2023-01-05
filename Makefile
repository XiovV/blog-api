.PHONY: swagger
swagger:
	swag init -g server/server.go

.PHONY: migrate
	migrate -database ${POSTGRES_URL} -path migrations/ up