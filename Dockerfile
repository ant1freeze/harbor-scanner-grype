# Simple Dockerfile with real Grype
FROM alpine:3.19

# Install basic dependencies including cron
RUN apk add --no-cache curl ca-certificates dcron

# Create scanner user
RUN adduser -u 10000 -D -g '' scanner scanner

# Create directories
RUN mkdir -p /home/scanner/.cache/grype /home/scanner/.cache/reports /home/scanner/bin /app

# Copy the compiled binary, config files, and scripts
COPY scanner-grype-linux /home/scanner/bin/scanner-grype
COPY grype-config.yaml /home/scanner/.grype.yaml
COPY risk-config.yaml /app/risk-config.yaml
COPY update-grype-db.sh /usr/local/bin/update-grype-db.sh
COPY start.sh /usr/local/bin/start.sh


# Install Grype manually by downloading the binary directly
RUN GRYPE_VERSION="0.100.0" && \
    GRYPE_ARCH="amd64" && \
    GRYPE_OS="linux" && \
    curl -L "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_${GRYPE_OS}_${GRYPE_ARCH}.tar.gz" -o /tmp/grype.tar.gz && \
    tar -xzf /tmp/grype.tar.gz -C /tmp && \
    mv /tmp/grype /usr/local/bin/grype && \
    chmod +x /usr/local/bin/grype && \
    rm -f /tmp/grype.tar.gz

# Download Grype vulnerability database during build
RUN /usr/local/bin/grype db update

# Set permissions and setup cron
RUN chmod +x /home/scanner/bin/scanner-grype && \
    chmod +x /usr/local/bin/update-grype-db.sh && \
    chmod +x /usr/local/bin/start.sh && \
    chown -R scanner:scanner /home/scanner && \
    echo "0 0 * * * /usr/local/bin/update-grype-db.sh >> /var/log/grype-update.log 2>&1" | crontab -

# Set environment variables
ENV GRYPE_VERSION=latest
ENV PATH="/home/scanner/bin:${PATH}"

# Switch to scanner user
USER scanner

# Set working directory
WORKDIR /home/scanner

# Expose port
EXPOSE 8080

# Run the application with cron
ENTRYPOINT ["/usr/local/bin/start.sh"]
