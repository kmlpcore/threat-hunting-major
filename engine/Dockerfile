# One image for every engine service; the compose entrypoint picks the role.
# Build context is the repository root.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 \
    REPO_ROOT=/app PYTHONPATH=/app

WORKDIR /app
COPY engine/pyproject.toml engine/pyproject.toml
RUN python -c "import tomllib; p = tomllib.load(open('engine/pyproject.toml', 'rb'))['project']; \
print('\n'.join(p['dependencies'] + p['optional-dependencies']['dev']))" > /tmp/requirements.txt \
 && pip install -r /tmp/requirements.txt

COPY engine engine
COPY schemas schemas
COPY scenarios scenarios
COPY policies policies
COPY benchmarks benchmarks
COPY tests tests

RUN useradd --create-home --uid 10001 engine && chown -R engine /app
USER engine
CMD ["python", "-m", "engine.cli", "--help"]
