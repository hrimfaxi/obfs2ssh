FROM ubuntu:latest
MAINTAINER Hrimfaxi <outmatch@gmail.com>

ENV DEPENDENCIES git-core python privoxy ssh ca-certificates
ENV BASEDIR /tmp/obfs2SSH

ENV SRCPORT 8117
ENV DSTPORT 8118
ENV KEY 2f86ca292daf89e41acb186b82f63d7d
ENV NOGFW_KEY "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEA1+qMw6TGpINApKjQPHcMYWHi/KztxNkzwS1RzTUXsmpI/So+qAKIHfPE84ibg0U6Z0wwdQKzzlJXT5OyQ39pHlMdxjGjV154FBCRTXR52/iQldBbKeJqi8fl6Zg4XbSI2h/CPBFMdReC4W8ll+8uTf+nRPHDncX8k8o0fUGMlr3OLj+NmcGO7e2zcyWgFxit/zBVWzbLwgMdtlMstvulc91CwBO6+JkpXrIZVjSE8oLTb3xVBEflUlZDPByTaAYAnh0Tz4yQ1SlxOdFrDBs6VkO+/fuCWkESxeoGYjTnyquaJo261hhDU2VByhVHd/2SJu1qsfEVPbEUfUfgZfBoeQ=="
ENV SSHPORT 2222

# Set up building environment
RUN apt-get update \
 && apt-get install --no-install-recommends -y $DEPENDENCIES

# Get the latest code
RUN git clone https://github.com/hrimfaxi/obfs2ssh $BASEDIR
WORKDIR $BASEDIR
RUN cp tcprelay_secret_exp.py /usr/local/bin \
 && sed -i "s/^listen-address\s\+localhost:8118/listen-address 127.0.0.1:$DSTPORT/g" /etc/privoxy/config \
 && sed -i 's/^toggle\s\+1/toggle 0/g' /etc/privoxy/config \
 && sed -i 's/^logfile\s\+logfile/#logfile logfile/g' /etc/privoxy/config \
 && useradd -s /bin/false -u 499 nogfw \
 && echo "nogfw:$(ps -ef|md5sum|awk '{print $1}')" | chpasswd \
 && echo 'UseDNS no \n\
ClientAliveInterval 300 \n\
Match user nogfw \n\
    PasswordAuthentication no \n\
' >> /etc/ssh/sshd_config \
 && mkdir -p /home/nogfw/.ssh \
 && echo "$NOGFW_KEY" >> /home/nogfw/.ssh/authorized_keys \
 && chmod 700 /home/nogfw \
 && chown -R nogfw:nogfw /home/nogfw

# Tear down building environment and delete git repository
WORKDIR /
RUN rm -rf $BASEDIR/obfs2SSH \
  && apt-get --purge autoremove -y git-core ca-certificates

EXPOSE $SSHPORT/tcp
ADD entrypoint /
ENTRYPOINT ["/entrypoint"]
#CMD [ "/bin/bash"]
