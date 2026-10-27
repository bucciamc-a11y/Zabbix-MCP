# syntax=docker/dockerfile:1
FROM python:3.12-slim-bookworm AS build
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN pip install uv
WORKDIR /src
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable --python /usr/local/bin/python

FROM python:3.12-slim-bookworm
LABEL org.opencontainers.image.title="zabbix-mcp" \
      org.opencontainers.image.description="MCP server for the Zabbix 7.4 API"
RUN useradd --system --uid 10001 --user-group --no-create-home --shell /usr/sbin/nologin zmcp \
 && install -d -o 10001 -g 10001 -m 0700 /data
COPY --from=build /src/.venv /app/.venv
ENV PATH=/app/.venv/bin:$PATH \
    PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 \
    DATA_DIR=/data MCP_TRANSPORT=http MCP_HOST=0.0.0.0 MCP_PORT=8000
USER 10001:10001
VOLUME ["/data"]
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["python", "-c", "import os,urllib.request as u; u.urlopen('http://127.0.0.1:'+os.environ.get('MCP_PORT','8000')+'/healthz', timeout=4)"]
ENTRYPOINT ["zabbix-mcp"]
CMD ["serve"]
