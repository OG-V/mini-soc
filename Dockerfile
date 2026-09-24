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

EXPOSE 22

# Start rsyslog (so sshd's syslog messages land in /var/log/auth.log), start tcpdump
# in the background capturing inbound SYN packets (catches port scans that never
# speak SSH and therefore never appear in auth.log), then sshd in the foreground
CMD ssh-keygen -A && \
    rm -f /run/rsyslogd.pid && \
    rsyslogd && \
    (tcpdump -i eth0 -tttt -n -l 'tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn' > /var/log/tcpdump-syn.log 2>&1 &) && \
    /usr/sbin/sshd -D
