FROM alpine:3.18

# Install some packages that might have vulnerabilities
RUN apk add --no-cache \
    curl \
    wget \
    openssl \
    bash

# Create a simple test file
RUN echo "Test image for vulnerability scanning" > /test.txt

CMD ["/bin/sh"]
