# syntax=docker/dockerfile:1
FROM quay.io/centos/centos:stream9

# Prevent interactive package-manager prompts.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install Python, the RPM Python bindings, and build/runtime dependencies.
RUN dnf -y update && \
    dnf -y install \
        python3 \
        python3-pip \
        python3-devel \
        python3-rpm \
        gcc \
        gcc-c++ \
        make \
        ca-certificates && \
    dnf clean all && \
    rm -rf /var/cache/dnf

# Install Python dependencies first to improve Docker layer caching.
COPY requirements.txt .

RUN python3 -m pip install --upgrade pip setuptools wheel && \
    python3 -m pip install -r requirements.txt

# Copy the application, processor, and release inventory directory.
COPY app.py .
COPY cve_processor.py .
COPY releasebuilds ./releasebuilds

# NiceGUI listens on port 3251.
EXPOSE 3251

# Run as a non-root user where possible.
RUN useradd --create-home --shell /sbin/nologin appuser && \
    chown -R appuser:appuser /app

USER appuser

CMD ["python3", "app.py"]

#docker build -t cve-tool-service .
#docker run -d \
#  --name cvetool \
#  -p 8080:3251 \
#  -v /path/to/config:/app/config \
#  -v /path/to/logs:/app/logs \
#  -v /path/to/releasebuilds:/app/releasebuilds \
#  -e CVE_DEBUG=1 \
#  cve-tool-service
#
#docker run -d `
#  --name cvetool `
#  -p 8080:3251 `
#  -v /path/to/config:/app/config `
#  -v /path/to/logs:/app/logs `
#  -v /path/to/releasebuilds:/app/releasebuilds `
#  -e CVE_DEBUG=1 `
#  cve-tool-service

