FROM golang:1.23-alpine AS builder

RUN apk add --no-cache git

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -o ssh-server .

FROM alpine:latest

RUN apk add --no-cache openssh openssh-keygen sudo bash shadow git curl kubectl fzf bash-completion ncurses ncurses-terminfo fastfetch iproute2 iputils busybox-extras iptables libcap arp-scan eza zsh zsh-vcs socat

# Sudoers Konfiguration für User-Wechsel
RUN echo "root ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers && \
    echo "Defaults:%root !requiretty" >> /etc/sudoers

# SSH Host Keys generieren
RUN ssh-keygen -A

# Create directories
RUN mkdir -p /tmp/chroots /var/lib/ssh-users /var/lib/ssh-keys

# Copy binary and entrypoint
COPY --from=builder /app/ssh-server /usr/local/bin/ssh-server
COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Volume for persistent SSH keys
VOLUME ["/var/lib/ssh-keys"]

EXPOSE 2222

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["/usr/local/bin/ssh-server"]
