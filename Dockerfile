FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

RUN groupadd -r vectra && useradd -r -g vectra -d /app -s /bin/bash vectra

# Copy the build context required by hatchling so it can build a wheel.
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY src/ ./src/

# Optional: include a tenants.yaml at build time if one exists. Most users
# will mount it at runtime instead.
COPY tenants.yaml* ./

# Install uv, then install the package (and its locked deps) into a venv.
RUN pip install --no-cache-dir uv && \
    uv sync --frozen --no-dev

RUN chown -R vectra:vectra /app && \
    chmod -R 755 /app

USER vectra

# The console script `vectra-ai-mcp-server` lives in the venv created by uv sync.
ENV PATH="/app/.venv/bin:${PATH}"

ENV VECTRA_MCP_TRANSPORT=stdio
ENV VECTRA_MCP_HOST=0.0.0.0
ENV VECTRA_MCP_PORT=8000
ENV VECTRA_MCP_DEBUG=false

LABEL maintainer="Vectra AI MCP Server" \
      description="MCP server for Vectra AI Platform" \
      security.non-root="true" \
      security.user="vectra"

LABEL io.docker.server.metadata="name: vectra-ai-rux-mcp-server\n\
image: mcp/vectra-ai-rux-mcp-server\n\
type: server\n\
config:\n\
  secrets:\n\
    - name: vectra-ai-rux-mcp-server.vectra_client_secret\n\
      env: VECTRA_CLIENT_SECRET\n\
      example: '••••••••'\n\
  environment:\n\
    - name: VECTRA_BASE_URL\n\
      value: '{{vectra_base_url}}'\n\
      example: 'https://1234.abc.portal.vectra.ai'\n\
    - name: VECTRA_CLIENT_ID\n\
      value: '{{vectra_client_id}}'\n\
      example: '1234567890abcdef'"

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD if [ "$VECTRA_MCP_TRANSPORT" = "stdio" ]; then \
            echo "Stdio transport - no HTTP endpoint to check" && exit 0; \
        else \
            curl -f --connect-timeout 5 --max-time 10 http://localhost:${VECTRA_MCP_PORT}/ || exit 1; \
        fi

ENTRYPOINT ["vectra-ai-mcp-server"]
CMD []
