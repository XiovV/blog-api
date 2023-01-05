Simple API Template

## Overview
The purpose of this project is to show how I structure my REST API projects.

## Features
This API has the following features:
- Clean and easy to understand structure
- 2-Factor Authentication using [TOTP](https://en.wikipedia.org/wiki/Time-based_one-time_password)
- Role management with [RBAC](https://en.wikipedia.org/wiki/Role-based_access_control)
- Automatically generated docs with [go-swagger](https://goswagger.io/)
- [12 Factor](https://12factor.net/) compliant

## Project structure
### `cmd/app.go`
Initializes all of the dependencies for the `Server`.
### `cmd/logger.go`
Contains a function which initializes the [Zap](https://github.com/uber-go/zap) logger.

### `config`
[cleanenv](https://github.com/ilyakaznacheev/cleanenv) is used for handling the configuration. No config files are used,
all configuration parameters should be stored in environment variables. Fields marked with `env-required: "true"` have to be set
manually or the server will not start up.

### `docs`
Auto-generated swagger documentation by [swag](https://github.com/swaggo/swag) library.
Nothing needs to be manually edited here.

### `migrations`
Contains all of the necessary migrations for the database, created with [migrate](https://github.com/golang-migrate/migrate).
Before running the migrations with `make migrate`, make sure to set the POSTGRES_URL environment variable. Reference: [migrate PostgreSQL](https://github.com/golang-migrate/migrate/blob/master/database/postgres/TUTORIAL.md).
