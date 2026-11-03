FROM python:3.13-slim

WORKDIR /app

COPY pyproject.toml /app/
COPY ./src/guardette /app/src/guardette
RUN pip install --no-cache-dir .

COPY main.py /app/

ENV GUARDETTE_POLICY_PATH=/app/config/policy.yml
ENV PORT=8000

EXPOSE 8000
# exec so uvicorn is PID 1 and receives SIGTERM for a graceful shutdown.
CMD ["sh", "-c", "exec uvicorn main:app --host 0.0.0.0 --port ${PORT}"]
