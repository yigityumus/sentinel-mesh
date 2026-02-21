FROM python:3.11-slim

WORKDIR /app

# Install Poetry
RUN pip install --no-cache-dir poetry

# Copy only dependency metadata first (better caching)
COPY pyproject.toml poetry.lock* ./

# Install deps into system Python (no venv) + no dev deps in container
RUN poetry config virtualenvs.create false \
 && poetry install --no-interaction --no-ansi --only main --no-root

# Copy application code
COPY app ./app

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8001"]
