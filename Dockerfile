# Stage 1: Build stage
FROM python:3.11-slim as builder

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Stage 2: Runtime stage
FROM python:3.11-slim

WORKDIR /app

# Copy only installed packages
COPY --from=builder /root/.local /root/.local

# Create non-root user FIRST
RUN useradd -m -u 1000 appuser

# Copy installed packages to appuser's directory and set permissions
RUN cp -r /root/.local /home/appuser/.local && \
    chown -R appuser:appuser /home/appuser/.local

# Set PATH for appuser
ENV PATH=/home/appuser/.local/bin:$PATH

# Copy application code and set ownership
COPY --chown=appuser:appuser ./app ./app

# Switch to non-root user
USER appuser

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]