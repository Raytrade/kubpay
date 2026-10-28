FROM golang:1.26-alpine AS build
WORKDIR /src

RUN apk add --no-cache ca-certificates git
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/kubpay ./cmd/server

FROM alpine:3.22
RUN apk add --no-cache ca-certificates tzdata && addgroup -S kubpay && adduser -S -G kubpay kubpay
WORKDIR /app
COPY --from=build /out/kubpay /app/kubpay
COPY --from=build /src/migrations /app/migrations
USER kubpay
ENV PORT=8080
EXPOSE 8080
ENTRYPOINT ["/app/kubpay"]
