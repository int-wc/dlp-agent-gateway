FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY dlp_gateway ./dlp_gateway
RUN pip install --no-cache-dir . && useradd --uid 10001 --create-home gateway && mkdir /data && chown gateway:gateway /data
USER gateway
ENV DLP_DB_PATH=/data/dlp.db
EXPOSE 8080
CMD ["uvicorn", "dlp_gateway.main:app", "--host", "0.0.0.0", "--port", "8080"]
