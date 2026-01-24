# Multi-stage Dockerfile for SSO service
# 
# Build from parent directory that contains both sso/ and protos/:
#   docker build -t sso:latest -f sso/Dockerfile .
#
# Or remove the replace directive in go.mod and build from sso/:
#   docker build -t sso:latest .

# Build stage
FROM golang:1.25-alpine AS builder

WORKDIR /build

# Install git for fetching dependencies
RUN apk add --no-cache git

# Copy protos (for local replace directive)
COPY protos/ /build/protos/

# Copy sso source
COPY sso/ /build/sso/

WORKDIR /build/sso

# Download dependencies
RUN go mod download

# Build the main application
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /bin/sso ./cmd/sso

# Build the db init tool
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /bin/dbinit ./cmd/migrator

# Runtime stage
FROM alpine:3.19

WORKDIR /app

# Install ca-certificates for HTTPS and timezone data
RUN apk --no-cache add ca-certificates tzdata

# Create non-root user
RUN adduser -D -g '' appuser

# Copy binaries from builder
COPY --from=builder /bin/sso /app/sso
COPY --from=builder /bin/dbinit /app/dbinit

# Switch to non-root user
USER appuser

# Expose gRPC port
EXPOSE 50051

# Default command
CMD ["/app/sso"]
