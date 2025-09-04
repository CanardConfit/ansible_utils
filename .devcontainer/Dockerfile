FROM mcr.microsoft.com/devcontainers/python:3.12-bookworm

ARG MITOGEN_VERSION=0.3.21

USER root

RUN apt update && apt install -y gnupg software-properties-common zsh libonig-dev net-tools dnsutils iputils-ping

RUN MITOGEN_VERSION=$(curl -s https://api.github.com/repos/mitogen-hq/mitogen/releases/latest | jq -r .tag_name | sed 's/^v//') && \
    curl -L https://github.com/mitogen-hq/mitogen/releases/download/v$MITOGEN_VERSION/mitogen-$MITOGEN_VERSION.tar.gz | \
    tar -xz -C /opt && \
    mv /opt/mitogen-$MITOGEN_VERSION /opt/mitogen

RUN pip install ansible-dev-tools

VOLUME /var/lib/containers

ENTRYPOINT ["/opt/builder/bin/entrypoint", "dumb-init"]
CMD ["zsh"]
