FROM golang:1.26-alpine AS build
WORKDIR /src

RUN apk add --no-cache ca-certificates git
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/kubpay ./cmd/server

FROM alpine:3.22
RUN apk add --no-cache ca-certificates tzdata postgresql-client && addgroup -S kubpay && adduser -S -G kubpay kubpay
WORKDIR /app
COPY --from=build /out/kubpay /app/kubpay
COPY --from=build /src/migrations /app/migrations
USER kubpay
ENV PORT=8080
EXPOSE 8080
# Apply idempotent schema migrations before the server starts. Never start with an uninitialized ledger.
ENTRYPOINT ["/bin/sh", "-c", "psql \"$DATABASE_URL\" -v ON_ERROR_STOP=1 -f /app/migrations/001_init.sql && exec /app/kubpay"]
