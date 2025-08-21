ARG PLATFORM=linux/amd64
ARG REGISTRY_VERSION=3.0.0

FROM --platform=${PLATFORM} registry:${REGISTRY_VERSION}

ARG ECR_HELPER_VERSION=0.10.1
RUN wget -O /usr/bin/docker-credential-ecr-login "https://amazon-ecr-credential-helper-releases.s3.us-east-2.amazonaws.com/${ECR_HELPER_VERSION}/linux-amd64/docker-credential-ecr-login" && \
    chmod 755 /usr/bin/docker-credential-ecr-login

COPY config.json /.docker/config.json

