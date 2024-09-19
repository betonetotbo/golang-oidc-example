docker-build:
	docker compose -f deployments/docker-compose.yaml -p go build

build:
	go build -o oidc ./cmd/main.go

run:
	PORT=8081 ISSUER=http://localhost:8080/realms/my-realm CLIENT_ID=my-client CLIENT_SECRET=W3aCgDs5SN7LED5akIk0yyq9DXzCeznJ go run ./cmd/main.go

up:
	docker compose -f deployments/docker-compose.yaml -p go up -d

down:
	docker compose -f deployments/docker-compose.yaml -p go down

logs:
	docker compose -f deployments/docker-compose.yaml -p go logs keycloak --follow

.PHONY: docker-build build run up down logs