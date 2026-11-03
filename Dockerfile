# One image for api, ui and the one-shot ingest job.
FROM python:3.11-slim

COPY --from=ghcr.io/astral-sh/uv:0.12.2 /uv /usr/local/bin/uv
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PROJECT_ENVIRONMENT=/opt/venv

WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src ./src
COPY knowledge_base ./knowledge_base
RUN uv sync --frozen --no-dev \
    && groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid 10001 --create-home app \
    && mkdir -p /app/data && chown app /app/data

USER app
ENV PATH="/opt/venv/bin:$PATH" DATA_DIR=/app/data
EXPOSE 8000 8501
CMD ["uvicorn", "pam_copilot.api:app", "--host", "0.0.0.0", "--port", "8000"]
