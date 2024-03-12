FROM ubuntu:latest

###################################
# Install Ubuntu Default Toolset
###################################
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get -y upgrade && \
    apt-get -y install \
        wordlists \
        iputils-ping && \
    apt-get clean && \
    apt-get -y autoremove

###################################
# Install VNC
###################################
RUN apt-get -y install \
        ubuntu-gnome-default-settings\
        xfce4 \ 
        dbus-x11 \
        xorg \
        tigervnc* && \
    apt-get -y remove xfce4-power-manager-plugins && \
    apt-get clean

###################################
# Setup SSH Server
###################################
# RUN apt-get -y install openssh-server && apt-get clean && \
#     sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config

###################################
# Create Non-Root User
###################################
ARG LOGINUSER=ubuntu
ARG LOGINPASS=SecretPass123
RUN useradd -m -s /bin/bash ${LOGINUSER} && \
    # usermod -a -G sudo ${LOGINUSER} && \
    echo "${LOGINUSER}:${LOGINPASS}" | chpasswd && \
    touch /home/${LOGINUSER}/.hushlogin
WORKDIR /home/${LOGINUSER}


RUN echo 'ubuntu ALL = (root) NOPASSWD: /tmp/run.sh' >> /etc/sudoers
RUN mkdir /home/ubuntu/.vnc
RUN touch /home/ubuntu/.Xauthority
RUN /bin/bash -c 'vncpasswd -f <<< ubuntu23 > "/home/ubuntu/.vnc/passwd"'
RUN chmod 400 /home/ubuntu/.vnc/passwd
RUN echo "su -c 'USER=ubuntu vncserver -localhost=0 -alwaysshared -rfbauth /home/ubuntu/.vnc/passwd' - ubuntu" >> /tmp/run.sh
RUN echo "service postgresql start" >> /tmp/run.sh
RUN echo "tail -f /dev/null" >> /tmp/run.sh
RUN chown -R ubuntu  /home/ubuntu 
RUN chmod +x /tmp/run.sh
ENTRYPOINT ["/bin/sh","-c","sudo /tmp/run.sh"]
