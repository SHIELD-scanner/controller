# syntax=docker/dockerfile:1

FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN cd cmd/controller && go build -o /app/controller

FROM alpine:3.19
WORKDIR /app
COPY --from=builder /app/controller ./controller
COPY config.local.json ./config.local.json
COPY logs ./logs
ENTRYPOINT ["./controller"]
