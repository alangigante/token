FROM golang:1.23-alpine AS builder

WORKDIR /app

COPY go.mod ./
RUN go mod download

COPY . .

ARG TARGET=cell
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/server ./cmd/${TARGET}

FROM alpine:3.19

RUN apk --no-cache add ca-certificates

COPY --from=builder /app/server /server

ENTRYPOINT ["/server"]
