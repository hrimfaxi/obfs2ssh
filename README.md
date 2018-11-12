安装新的obfs2ssh服务器 {#_安装新的obfs2ssh服务器}
======================

-   基于流量混淆

-   不要使用obfs3，死的更快

-   基于ubuntu 16.04 LTS

**先更新.**

``` {.bash}
apt-get update && apt-get upgrade
```

**安装privoxy (http代理服务器)，修改设置，并重启.**

``` {.bash}
apt-get install privoxy
sed -i 's/^listen-address\s\+localhost:8118/listen-address 127.0.0.1:8118/g' /etc/privoxy/config
sed -i 's/^toggle\s\+1/toggle 0/g' /etc/privoxy/config
sed -i 's/^logfile\s\+logfile/#logfile logfile/g' /etc/privoxy/config
systemctl restart privoxy
```

**添加nogfw用户，随机化密码，并只允许nogfw使用公私钥方式登录，并安装sshguard.**

``` {.bash}
useradd -s /bin/false -u 499 nogfw
echo "nogfw:$(ps -ef|md5sum|awk '{print $1}')" | chpasswd
cat >> /etc/ssh/sshd_config << EOF
UseDNS no
ClientAliveInterval 300
Match user nogfw
    PasswordAuthentication no
EOF
systemctl restart sshd
apt-get install sshguard
```

**为nogfw用户添加ssh公钥(你可以换自己的公钥，需和客户端的Data/nogfw.key(ssh)或Data/nogfw.ppk(plink)相对应).**

``` {.bash}
mkdir -p /home/nogfw/.ssh
cat >> /home/nogfw/.ssh/authorized_keys << EOF
ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEA1+qMw6TGpINApKjQPHcMYWHi/KztxNkzwS1RzTUXsmpI/So+qAKIHfPE84ibg0U6Z0wwdQKzzlJXT5OyQ39pHlMdxjGjV154FBCRTXR52/iQldBbKeJqi8fl6Zg4XbSI2h/CPBFMdReC4W8ll+8uTf+nRPHDncX8k8o0fUGMlr3OLj+NmcGO7e2zcyWgFxit/zBVWzbLwgMdtlMstvulc91CwBO6+JkpXrIZVjSE8oLTb3xVBEflUlZDPByTaAYAnh0Tz4yQ1SlxOdFrDBs6VkO+/fuCWkESxeoGYjTnyquaJo261hhDU2VByhVHd/2SJu1qsfEVPbEUfUfgZfBoeQ==
EOF
chmod 700 /home/nogfw
chown -R nogfw:nogfw /home/nogfw
```

**下载obfs2ssh，安装并运行流量混淆脚本.**

``` {.bash}
apt-get install python
git clone https://github.com/hrimfaxi/obfs2ssh
cd obfs2ssh
cp tcprelay_secret_exp.py /usr/local/bin
cat > /etc/systemd/system/tcpreplay_secret_exp.service <<< EOF
[Unit]
Description=tcp replay random padding service

[Service]
Type=simple
Environment="SRCPORT=8117"
Environment="DSTPORT=8118"
Environment="KEY=2f86ca292daf89e41acb186b82f63d7d"
EnvironmentFile=-/etc/default/tcpreplay_secret_exp
ExecStart=/usr/bin/env python2 /usr/local/bin/tcprelay_secret_exp.py -p \$SRCPORT -P \$DSTPORT -m 2:\${KEY}
User=nobody
CapabilityBoundingSet=~CAP_SYS_PTRACE
PrivateTmp=true
ProtectSystem=full

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl enable tcpreplay_secret_exp
sudo systemctl start tcpreplay_secret_exp

```

如需要修改流量混淆密码，需要在obfs2ssh客户端bandwithKey和服务器上/etc/l同时修改为16字节大小的hex字符。
此脚本监听在8117端口上，负责在服务器将客户端的伪数据去除后送真正的http代理端口。

**最后的优化，安装google bbr，并优化sysctl网络参数.**

``` {.bash}
# 到ppa kernel去选一个>4.11的稳定内核
cat | wget -i - << EOF
http://kernel.ubuntu.com/~kernel-ppa/mainline/v4.13.7/linux-headers-4.13.7-041307_4.13.7-041307.201710141430_all.deb
http://kernel.ubuntu.com/~kernel-ppa/mainline/v4.13.7/linux-headers-4.13.7-041307-generic_4.13.7-041307.201710141430_amd64.deb
http://kernel.ubuntu.com/~kernel-ppa/mainline/v4.13.7/linux-image-4.13.7-041307-generic_4.13.7-041307.201710141430_amd64.deb
EOF
dpkg -i linux-*.deb
rm linux-*.deb
cat >> /etc/sysctl.conf << EOF
# Accept IPv6 advertisements when forwarding is enabled
net.ipv6.conf.all.accept_ra = 2

# Congestion
net.ipv4.tcp_allowed_congestion_control = hybla cubic reno lp bbr
#net.ipv4.tcp_congestion_control = hybla
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc=fq

# retries
#net.ipv4.tcp_retries1 = 3
#net.ipv4.tcp_retries2 = 5
#net.ipv4.tcp_syn_retries = 2
#net.ipv4.tcp_synack_retries = 2

# Memory
net.ipv4.tcp_wmem = 4096        65536 16777216
net.ipv4.tcp_rmem = 4096        327680 16777216
net.ipv4.tcp_mem = 327680 327680 16777216
net.core.rmem_default = 327680
net.core.wmem_default = 65536
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216

# Misc
# Enable ECN on both incoming and outgoing connections
net.ipv4.tcp_ecn = 2
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_tw_recycle = 0
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_frto = 2
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_window_scaling = 1
net.ipv4.ip_no_pmtu_disc = 0
net.ipv4.tcp_keepalive_probes = 3
net.ipv4.tcp_low_latency=0

# No slow-start after idle TCP connection (noGFW)
net.ipv4.tcp_slow_start_after_idle=0
EOF
```

**重启即可使用obfs2ssh客户端连接.**

``` {.bash}
reboot
```

\# 客户端

-   main.obfs2Addr 应为 &lt;ip&gt;:22 (ssh端口)

-   main.usePlainSSH 应为yes

-   main.useBandWidthObfs 应为yes

-   main.bandwidthPort main.bandwidthKey应与服务器上/etc/l一致

-   main.bandwidthListenAddress
    全局监听应为0.0.0.0，只监听环回接口应为127.0.0.1

-   main.extraOpts 推荐参数为-C -o
    ServerAliveInterval=30(ssh)或-C (plink)

**测试速度：.**

``` {.bash}
# 基本连接
curl -x localhost:8118 g.cn
# 下载约10M
curl -x localhost:8118 -O http://kernel.ubuntu.com/~kernel-ppa/mainline/v4.13.7/linux-headers-4.13.7-041307_4.13.7-041307.201710141430_all.deb
# 下载约180M
curl -x localhost:8118 -OL "http://ftp.jaist.ac.jp/pub/eclipse/technology/epp/downloads/release/oxygen/1a/eclipse-java-oxygen-1a-linux-gtk-x86_64.tar.gz"
```
