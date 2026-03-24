FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src/ src/

RUN pip install --no-cache-dir . requests

ENV OLLAMA_HOST=http://host.docker.internal:11434

ENTRYPOINT ["argus-redact"]
CMD ["info"]
