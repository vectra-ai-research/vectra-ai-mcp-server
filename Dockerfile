# Use Python 3.12 slim image
FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user
RUN groupadd -r vectra && useradd -r -g vectra -d /app -s /bin/bash vectra

# Copy project files
COPY pyproject.toml uv.lock ./
COPY server.py config.py statics.py vectra_client.py ./
COPY tool/ ./tool/
COPY utils/ ./utils/
COPY prompt/ ./prompt/

# Install uv via pip and sync dependencies
RUN pip install --no-cache-dir uv && \
    uv sync --frozen

# Set ownership and permissions
RUN chown -R vectra:vectra /app && \
    chmod -R 755 /app && \
    chmod 644 /app/*.py

# Switch to non-root user
USER vectra

# Update PATH to include the virtual environment
ENV PATH="/app/.venv/bin:${PATH}"

# Set environment variables for MCP server
ENV VECTRA_MCP_TRANSPORT=stdio
ENV VECTRA_MCP_HOST=0.0.0.0
ENV VECTRA_MCP_PORT=8000
ENV VECTRA_MCP_DEBUG=false

# Labels
LABEL maintainer="Vectra AI MCP Server" \
      description="MCP server for Vectra AI Platform" \
      security.non-root="true" \
      security.user="vectra"

# Expose port for HTTP transports (SSE and Streamable HTTP)
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD if [ "$VECTRA_MCP_TRANSPORT" = "stdio" ]; then \
            echo "Stdio transport - no HTTP endpoint to check" && exit 0; \
        else \
            curl -f --connect-timeout 5 --max-time 10 http://localhost:${VECTRA_MCP_PORT}/ || exit 1; \
        fi

# Exec
CMD ["uv", "run", "server.py"]
