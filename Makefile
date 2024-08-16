test:
	go test ./...

build:
	go build -o bin/ctk cmd/ctk/ctk.go

run:
	go run cmd/ctk/ctk.go

fmt:
	go fmt ./...
