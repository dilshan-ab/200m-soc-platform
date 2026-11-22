FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
# WeasyPrint (PDF reports) system libraries
RUN apt-get update && apt-get install -y --no-install-recommends libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/* && useradd --system --uid 10001 --create-home soc
WORKDIR /srv
COPY pyproject.toml ./
RUN python - <<'PY' > requirements.txt
import tomllib
p = tomllib.load(open("pyproject.toml", "rb"))["project"]
print("\n".join(p["dependencies"] + p["optional-dependencies"]["pdf"] + p["optional-dependencies"]["connectors"]))
PY
RUN pip install -r requirements.txt
COPY app ./app
COPY data ./data
COPY migrations ./migrations
COPY alembic.ini ./
RUN mkdir -p /srv/reports && chown -R soc:soc /srv
USER soc
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:8000/healthz')" || exit 1
CMD ["sh", "-c", "alembic upgrade head && exec uvicorn app.main:create_app --factory --host 0.0.0.0 --port 8000 --proxy-headers --forwarded-allow-ips='*' --no-server-header"]
