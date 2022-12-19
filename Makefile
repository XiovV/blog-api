.PHONY: swagger
swagger:
	swagger generate spec --scan-models --output=docs/swagger.yaml