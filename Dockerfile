# -------- build stage --------
FROM golang:1.22 AS builder

WORKDIR /app
COPY . .

RUN go mod tidy
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o controller .

# -------- runtime stage --------
FROM gcr.io/distroless/base-debian12

WORKDIR /
COPY --from=builder /app/controller /controller

USER 65532:65532

ENTRYPOINT ["/controller"]