# OpenSSH built from source against musl, without PAM.
# Default is the last vulnerable release (10.6p1).
# Build with OPENSSH_VER=10.6p2 for the patched control.
FROM alpine:3.22

RUN apk add --no-cache build-base openssl-dev zlib-dev linux-headers curl

ARG OPENSSH_VER=10.6p1
RUN curl -fsSLo /tmp/openssh.tar.gz \
      https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-${OPENSSH_VER}.tar.gz \
 && mkdir -p /tmp/openssh && tar -xzf /tmp/openssh.tar.gz -C /tmp/openssh --strip-components=1 \
 && cd /tmp/openssh \
 && ./configure --prefix=/usr/local --sysconfdir=/etc/ssh \
      --with-privsep-path=/var/empty --with-privsep-user=sshd \
      --without-pam \
 && make -j"$(nproc)" \
 && addgroup -S sshd 2>/dev/null; adduser -S -D -H -s /sbin/nologin -G sshd sshd 2>/dev/null; \
    mkdir -p /var/empty \
 && cd /tmp/openssh && make install \
 && rm -rf /tmp/openssh /tmp/openssh.tar.gz

# alice: target account, shadow field forced to "*"
# bob:   salt donor with a real $6$ hash
# root:  "*" as shipped on Alpine 3.16+
RUN adduser -D -s /bin/sh alice \
 && sed -i 's/^alice:[^:]*:/alice:*:/' /etc/shadow \
 && adduser -D -s /bin/sh bob \
 && echo 'bob:CorrectHorseBatteryStaple' | chpasswd -c SHA512 \
 && sed -i 's/^root:[^:]*:/root:*:/' /etc/shadow

RUN /usr/local/bin/ssh-keygen -A \
 && printf '%s\n' \
      'PasswordAuthentication yes' \
      'PubkeyAuthentication yes' \
      'PermitRootLogin yes' \
      'LogLevel VERBOSE' >> /etc/ssh/sshd_config

EXPOSE 22
CMD ["/usr/local/sbin/sshd", "-D", "-e"]
