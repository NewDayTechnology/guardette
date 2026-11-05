FROM python:3.13-slim
 
WORKDIR /app
 
COPY pyproject.toml /app/
COPY ./src/guardette /app/src/guardette
RUN pip install --no-cache-dir .
 
COPY main.py /app/
COPY .guardette/policy.yml /app/config/policy.yml
 
RUN useradd --system --uid 10001 --no-create-home guardette
 
ENV GUARDETTE_POLICY_PATH=/app/config/policy.yml \
    PORT=8000 \
    PYTHONUNBUFFERED=1
 
EXPOSE 8000
 
USER 10001
CMD ["sh", "-c", "exec uvicorn main:app --host 0.0.0.0 --port ${PORT}"]
