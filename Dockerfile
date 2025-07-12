# Multi-stage build for codesucks-ai
FROM golang:1.21-alpine AS builder

# Install dependencies
RUN apk add --no-cache git python3 py3-pip

# Install Semgrep
RUN pip3 install --break-system-packages semgrep

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o codesucks-ai ./cmd/codesucks-ai

# Final stage
FROM python:3.11-alpine

# Install Semgrep in final image
RUN pip3 install --no-cache-dir semgrep

# Create non-root user
RUN adduser -D -s /bin/sh appuser

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/codesucks-ai .
COPY --from=builder /app/configs ./configs

# Create results directory
RUN mkdir -p results && chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Make binary executable
RUN chmod +x codesucks-ai

# Expose port (if needed for web interface)
EXPOSE 8080

# Default command
ENTRYPOINT ["./codesucks-ai"]

# Default arguments (can be overridden)
CMD ["-help"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD ./codesucks-ai -help || exit 1

# Labels
LABEL maintainer="codesucks-ai" \
      description="AI-Powered Security Analysis Tool" \
      version="1.0.0" \
      org.opencontainers.image.source="https://github.com/asii-mov/codesucks-ai"