FROM mcr.microsoft.com/devcontainers/python:1-3.12-bookworm@sha256:7876580dc67fd460fd962f004cbeb480027e9bbc0657096f1087db11f9eaff39

USER root

# The pinned base image contains an expired Yarn repository key. The project does
# not use Yarn, and disabling only that source lets Dev Container Features update
# Debian package metadata without weakening signature verification.
RUN if [ -f /etc/apt/sources.list.d/yarn.list ]; then \
        mv /etc/apt/sources.list.d/yarn.list \
          /etc/apt/sources.list.d/yarn.list.disabled; \
    fi
