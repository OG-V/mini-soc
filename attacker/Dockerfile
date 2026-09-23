FROM kalilinux/kali-rolling

RUN apt-get update && \
    apt-get install -y hydra nmap openssh-client curl && \
    apt-get clean

WORKDIR /attacks

RUN printf "123456\npassword\npassword123\nadmin\nletmein\n" > /attacks/passwords.txt
