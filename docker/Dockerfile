# Multi-stage build for codesucks-ai with Claude Code SDK and Agent support
FROM golang:1.21-alpine AS builder

# Install dependencies
RUN apk add --no-cache git python3 py3-pip curl wget

# Install Semgrep and Claude Code SDK
RUN pip3 install --break-system-packages semgrep claude-code-sdk

# Install TruffleHog binary
RUN wget -O /tmp/trufflehog.tar.gz https://github.com/trufflesecurity/trufflehog/releases/latest/download/trufflehog_3.63.7_linux_amd64.tar.gz && \
    tar -xzf /tmp/trufflehog.tar.gz -C /usr/local/bin/ && \
    chmod +x /usr/local/bin/trufflehog && \
    rm /tmp/trufflehog.tar.gz

# Set working directory
WORKDIR /app

# Copy go mod files
COPY src/go.mod src/go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY src/ .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o codesucks-ai ./cmd/codesucks-ai

# Final stage
FROM python:3.11-alpine

# Install required packages including Claude Code SDK
RUN apk add --no-cache curl wget && \
    pip3 install --no-cache-dir semgrep claude-code-sdk

# Install TruffleHog binary in final image
RUN wget -O /tmp/trufflehog.tar.gz https://github.com/trufflesecurity/trufflehog/releases/latest/download/trufflehog_3.63.7_linux_amd64.tar.gz && \
    tar -xzf /tmp/trufflehog.tar.gz -C /usr/local/bin/ && \
    chmod +x /usr/local/bin/trufflehog && \
    rm /tmp/trufflehog.tar.gz

# Create non-root user
RUN adduser -D -s /bin/sh appuser

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/codesucks-ai .
COPY --from=builder /app/configs ./configs
COPY --from=builder /app/docs ./docs

# Create agent workspace and session directories
RUN mkdir -p agents sessions results claude-agents vulnerable_code && \
    chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Make binary executable
RUN chmod +x codesucks-ai

# Expose port (if needed for web interface)
EXPOSE 8080

# Environment variables for Claude Code SDK
ENV CLAUDE_AGENTS_DIR=/app/claude-agents \
    CLAUDE_SESSION_DIR=/app/sessions \
    ANTHROPIC_API_KEY="" \
    CLAUDE_CODE_LOG_LEVEL=INFO

# Volume mounts for persistent data
VOLUME ["/app/sessions", "/app/results", "/app/claude-agents", "/app/vulnerable_code"]

# Default command
ENTRYPOINT ["./codesucks-ai"]

# Default arguments (can be overridden)
CMD ["-help"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD ./codesucks-ai -help || exit 1

# Labels
LABEL maintainer="codesucks-ai" \
      description="AI-Powered Security Analysis Tool with Claude Code SDK Agent Support" \
      version="2.0.0" \
      org.opencontainers.image.source="https://github.com/asii-mov/codesucks-ai" \
      features="claude-agents,parallel-analysis,docker-sandbox"