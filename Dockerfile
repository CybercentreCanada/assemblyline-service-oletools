FROM cccs/assemblyline-v4-service-base:latest

ENV SERVICE_PATH oletools_.oletools_.Oletools

USER root

# Get required apt packages
RUN apt-get update && apt-get install -y default-libmysqlclient-dev && rm -rf /var/lib/apt/lists/*

# Switch to assemblyline user
USER assemblyline

RUN pip install --no-cache-dir --user hachoir pcodedmp oletools && rm -rf ~/.cache/pip

# Copy Oletools service code
WORKDIR /opt/al_service
COPY . .

# Patch version in manifest
ARG version=4.0.0.dev1
USER root
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml

# Switch to assemblyline user
USER assemblyline