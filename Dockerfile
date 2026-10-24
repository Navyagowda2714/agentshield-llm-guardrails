FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    LLM_PROVIDER=offline

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir . && \
    useradd --create-home --uid 10001 appuser
USER appuser

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health').status==200 else 1)"

CMD ["uvicorn", "agentshield.api:app", "--host", "0.0.0.0", "--port", "8000"]
