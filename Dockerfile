FROM golang:1.24.2-alpine3.21 AS builder

WORKDIR /app

COPY go.mod ./
COPY go.sum* ./
RUN go mod download

COPY . .
RUN go build -o webdir -ldflags '-s -w' main.go

FROM alpine:3.21

RUN apk --no-cache add ca-certificates
COPY --from=builder /app/webdir /usr/local/bin/webdir

WORKDIR /data
ENTRYPOINT ["webdir"]
