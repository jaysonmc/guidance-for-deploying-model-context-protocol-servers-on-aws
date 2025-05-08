# Use Python 3.10 as the base image (more widely supported)
FROM python:3.13-slim

# Set working directory
WORKDIR /app

# Install required packages
RUN apt-get update && apt-get install -y curl && \
    pip install --upgrade pip && \
    pip install uv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml .
COPY uv.lock .
COPY weather.py .
COPY oauth_cognito.py .
COPY README.md .
COPY .python-version .

# Install dependencies using uv with --system flag
RUN uv pip install --system --requirement pyproject.toml

# Set proper permissions
RUN chmod +x weather.py

# Create a non-root user and group
RUN addgroup --system --gid 1001 appgroup && \
    adduser --system --uid 1001 --ingroup appgroup appuser

# Set appropriate ownership
RUN chown -R appuser:appgroup /app

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PORT=8080
ENV BASE_PATH=""

# Expose port for container
EXPOSE 8080

# Switch to non-root user
USER appuser

# Add simple healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8080${BASE_PATH}/ || exit 1

# Run the weather application
CMD ["python", "weather.py"]
