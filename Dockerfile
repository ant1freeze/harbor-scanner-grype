# Simple Dockerfile with real Grype
FROM alpine:3.19

# Install basic dependencies including Docker CLI and sudo
RUN apk add --no-cache curl ca-certificates docker-cli sudo

# Create docker group and scanner user
RUN addgroup -g 998 docker && \
    adduser -u 10000 -D -g '' scanner scanner && \
    adduser scanner docker && \
    echo 'scanner ALL=(ALL) NOPASSWD: /bin/tee' >> /etc/sudoers

# Create directories
RUN mkdir -p /home/scanner/.cache/grype /home/scanner/.cache/reports /home/scanner/bin

# Copy the compiled binary, config and hosts file
COPY scanner-grype-linux /home/scanner/bin/scanner-grype
COPY grype-config.yaml /home/scanner/.grype.yaml
COPY hosts /etc/hosts


# Install Grype manually by downloading the binary directly
RUN GRYPE_VERSION="0.100.0" && \
    GRYPE_ARCH="amd64" && \
    GRYPE_OS="linux" && \
    curl -L "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_${GRYPE_OS}_${GRYPE_ARCH}.tar.gz" -o /tmp/grype.tar.gz && \
    tar -xzf /tmp/grype.tar.gz -C /tmp && \
    mv /tmp/grype /usr/local/bin/grype && \
    chmod +x /usr/local/bin/grype && \
    rm -f /tmp/grype.tar.gz

# Set permissions
RUN chmod +x /home/scanner/bin/scanner-grype && \
    chown -R scanner:scanner /home/scanner

# Set environment variables
ENV GRYPE_VERSION=latest
ENV PATH="/home/scanner/bin:${PATH}"

# Switch to scanner user
USER scanner

# Set working directory
WORKDIR /home/scanner

# Expose port
EXPOSE 8080

# Run the application
ENTRYPOINT ["/home/scanner/bin/scanner-grype"]
