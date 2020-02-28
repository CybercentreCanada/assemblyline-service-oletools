FROM cccs/assemblyline-v4-service-base:latest

ENV SERVICE_PATH oletools_.oletools_.Oletools

# Get required apt packages
RUN apt-get update && apt-get install -y default-libmysqlclient-dev && rm -rf /var/lib/apt/lists/*

RUN pip install pcodedmp oletools && rm -rf ~/.cache/pip

# Switch to assemblyline user
USER assemblyline

# Copy APKaye service code
WORKDIR /opt/al_service
COPY . .