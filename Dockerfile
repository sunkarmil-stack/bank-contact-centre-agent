# syntax=docker/dockerfile:1
FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

# Pick up Debian security fixes released after the base image was built.
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*

COPY requirements.txt requirements-prod.txt ./
RUN pip install -r requirements-prod.txt

COPY ccagent ./ccagent
COPY data ./data
COPY static ./static
COPY evals ./evals
COPY scripts ./scripts
COPY services ./services

# non-root, read-only friendly
RUN useradd --uid 10001 --create-home app && mkdir -p /app/.data && chown -R app /app/.data
USER 10001
EXPOSE 8000 8080 8101 8102 8765
# Health checks are defined per service in docker-compose.yml (each service listens on its own port).
CMD ["uvicorn", "ccagent.api.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8080", "--workers", "2"]
