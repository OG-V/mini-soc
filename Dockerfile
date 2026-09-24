FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y openssh-server rsyslog sudo tcpdump && \
    mkdir /var/run/sshd

# Weak test account for brute-force testing
RUN useradd -m -s /bin/bash testuser && \
    echo "testuser:password123" | chpasswd

# Allow password authentication
RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config && \
    sed -i 's/#LogLevel INFO/LogLevel VERBOSE/' /etc/ssh/sshd_config

# Deliberate privilege-escalation vector: passwordless sudo for testuser,
# simulating a common real-world misconfiguration
RUN echo "testuser ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/testuser && \
    chmod 440 /etc/sudoers.d/testuser

# Pre-create an empty authorized_keys file so file-integrity monitoring has
# a stable baseline hash from container start, rather than treating the
# attacker's first write as a file-creation event
RUN mkdir -p /root/.ssh && \
    touch /root/.ssh/authorized_keys && \
    chmod 600 /root/.ssh/authorized_keys

COPY fim-watch.sh /usr/local/bin/fim-watch.sh
RUN chmod +x /usr/local/bin/fim-watch.sh

EXPOSE 22

# Start rsyslog (so sshd's syslog messages land in /var/log/auth.log), start
# tcpdump in the background capturing inbound SYN packets (catches port
# scans that never speak SSH), start the file-integrity watcher in the
# background (catches unauthorized changes to security-critical files),
# then sshd in the foreground
CMD ssh-keygen -A && \
    rm -f /run/rsyslogd.pid && \
    rsyslogd && \
    (tcpdump -i eth0 -tttt -n -l 'tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn' > /var/log/tcpdump-syn.log 2>&1 &) && \
    (/usr/local/bin/fim-watch.sh > /var/log/fim.log 2>&1 &) && \
    /usr/sbin/sshd -D
