FROM cccs/assemblyline-v4-service-base:latest

ENV SERVICE_PATH oletools_.oletools_.Oletools

USER root

# Get required apt packages
RUN apt-get update && apt-get install -y default-libmysqlclient-dev && rm -rf /var/lib/apt/lists/*

# Switch to assemblyline user
USER assemblyline

RUN pip install --no-cache-dir --user pcodedmp oletools && rm -rf ~/.cache/pip

# Copy APKaye service code
WORKDIR /opt/al_service
COPY . .