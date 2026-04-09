FROM python:3.13-slim AS builder

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.13-slim

WORKDIR /app

COPY --from=builder /install /usr/local

COPY clients/ ./clients/
COPY server.py .
COPY poller.py .
COPY db.py .
COPY healthcheck.py .

EXPOSE 3707

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python healthcheck.py || exit 1

CMD ["python", "server.py"]
