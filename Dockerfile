FROM golang:1.23-alpine

RUN apk add --no-cache gcc musl-dev

WORKDIR /app

COPY go.mod go.sum* ./
RUN go mod download

COPY . .

RUN go build -o ja4bench ./cmd/ja4bench/ja4bench.go

ENTRYPOINT ["./ja4bench"]
