ARG ALPINE_VERSION_NAME=latest

FROM alpine:${ALPINE_VERSION_NAME}

# Your Property
ARG USER=user
ARG USER_ID=1000
ARG GROUP_ID=1000

RUN apk update && apk add --no-cache go sudo \
    && mkdir WORKDIR \
    && addgroup -g ${GROUP_ID} ${USER} \
    && adduser -D -u ${USER_ID} -s /bin/sh -G ${USER} ${USER} \
    && adduser ${USER} wheel \
    && echo '%wheel ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers

WORKDIR /ngx_auth_mod

# TMP Docker Volume
VOLUME ["/ngx_auth_mod"]

ENV PATH="${PATH}:/root/go/bin"
ENV CGO_ENABLED=0

USER ${USER}

RUN go install -v github.com/go-delve/delve/cmd/dlv@latest