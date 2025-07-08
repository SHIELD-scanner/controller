APP_NAME=controller
CMD_DIR=cmd/controller

.PHONY: all build run clean tidy test

all: build

build:
	go build -o bin/$(APP_NAME) $(CMD_DIR)

run: build
	./bin/$(APP_NAME)

tidy:
	go mod tidy

clean:
	rm -rf bin

test:
	go test ./...
