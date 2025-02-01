FROM ghcr.io/ansible/community-ansible-dev-tools:latest

ARG MITOGEN_VERSION=0.3.21

USER root

RUN yum update -y && \
    yum clean all && \
    rm -rf /var/cache/yum

RUN curl -L https://github.com/mitogen-hq/mitogen/releases/download/v$MITOGEN_VERSION/mitogen-$MITOGEN_VERSION.tar.gz | \
    tar -xz -C /opt && \
    mv /opt/mitogen-$MITOGEN_VERSION /opt/mitogen

VOLUME /var/lib/containers

ENTRYPOINT ["/opt/builder/bin/entrypoint", "dumb-init"]
CMD ["zsh"]
