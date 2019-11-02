#!/bin/bash
openssl_ver="openssl-1.1.1d"
openssh_ver="openssh-8.1p1"
sshd_port="22"

install_zlib(){
    if [ -f /usr/local/zlib-1.2.11/lib/libz.a ];then
        echo "zlib-1.2.11 already exists!"
        return
    fi
    cd /tmp
    if [ ! -f zlib-1.2.11.tar.gz ];then
        wget https://zlib.net/zlib-1.2.11.tar.gz
        if [ $? -ne 0 ];then
            rm -rf zlib-1.2.11.tar.gz
            echo "zlib-1.2.11.tar.gz download failed!"
            exit 1
        fi
    fi
    tar xzf zlib-1.2.11.tar.gz
    cd zlib-1.2.11
    chmod +x configure
    ./configure --prefix=/usr/local/zlib-1.2.11
    if [ $? -ne 0 ];then
        echo "Failed to configure zlib!"
        exit 1
    fi
    make
    make install
    sed -i '$a\/usr/local/zlib-1.2.11/lib' /etc/ld.so.conf
    ldconfig
}

install_openssl(){
    if [ -f /usr/local/${openssl_ver}/bin/openssl ];then
        echo "${openssl_ver} already exists!"
        return
    fi
    if [ ! -f /etc/pki/tls/certs/ca-bundle.crt ];then
        echo "/etc/pki/tls/certs/ca-bundle.crt is not found!"
        exit 1
    fi
    cd /tmp
    if [ ! -f ${openssl_ver}.tar.gz ];then
        wget https://www.openssl.org/source/${openssl_ver}.tar.gz
        if [ $? -ne 0 ];then
            rm -rf ${openssl_ver}.tar.gz
            echo "${openssl_ver}.tar.gz download failed!"
            exit 1
        fi
    fi
    tar xzf ${openssl_ver}.tar.gz
    cd ${openssl_ver}
    chmod +x config
    ./config --prefix=/usr/local/${openssl_ver} --openssldir=/usr/local/${openssl_ver}/ssl -fPIC
    if [ $? -ne 0 ];then
        echo "Failed to config openssl!"
        exit 1
    fi
    make
    make install
    sed -i '$a\/usr/local/'${openssl_ver}'/lib' /etc/ld.so.conf
    ldconfig
    rm -rf /usr/local/${openssl_ver}/ssl/certs
    ln -s /etc/pki/tls/certs /usr/local/${openssl_ver}/ssl/certs
    ln -s /etc/pki/tls/certs/ca-bundle.crt /usr/local/${openssl_ver}/ssl/cert.pem
}

install_openssh(){
    cd /tmp
    if [ ! -f ${openssh_ver}.tar.gz ];then
        wget https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/${openssh_ver}.tar.gz
        if [ $? -ne 0 ];then
            rm -rf ${openssh_ver}.tar.gz
            echo "${openssh_ver}.tar.gz download failed!"
            exit 1
        fi
    fi
    tar xzf ${openssh_ver}.tar.gz
    cd ${openssh_ver}
    chmod +x configure
    # --with-pam
    ./configure --prefix=/usr --sysconfdir=/etc/ssh --with-ssl-dir=/usr/local/${openssl_ver} --with-zlib=/usr/local/zlib-1.2.11 --with-md5-passwords
    if [ $? -ne 0 ];then
        echo "Failed to configure openssh!"
        exit 1
    fi
    make
    if [ $? -ne 0 ];then
        echo "Failed to make openssh!"
        exit 1
    fi
    yum -y remove openssh-server openssh
    rm -rf /etc/ssh
    make install
    sed -i 's/#Port 22/Port '${sshd_port}'/' /etc/ssh/sshd_config
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
    sed -i 's/#UseDNS no/UseDNS no/' /etc/ssh/sshd_config
    sed -i 's/#TCPKeepAlive yes/TCPKeepAlive yes/' /etc/ssh/sshd_config
    sed -i 's/#ClientAliveInterval 0/ClientAliveInterval 60/' /etc/ssh/sshd_config
    sed -i 's/SELINUX=enforcing/SELINUX=disabled/' /etc/selinux/config
    cp -rf /tmp/${openssh_ver}/contrib/redhat/sshd.init /etc/init.d/sshd
    # cp -rf /tmp/${openssh_ver}/contrib/redhat/sshd.pam /etc/pam.d/sshd
    chmod +x /etc/init.d/sshd
    chmod 600 /etc/ssh/ssh_host_rsa_key
    chmod 600 /etc/ssh/ssh_host_ecdsa_key
    chmod 600 /etc/ssh/ssh_host_ed25519_key
    chkconfig --add sshd
    chkconfig sshd on
    service sshd restart
    num=$( iptables -nvL|grep -E 'ACCEPT.*tcp.*dpt:'${sshd_port}''|grep -v grep|wc -l )
    if [ ${num} -eq 0 ];then
        iptables -P INPUT DROP
        iptables -P FORWARD DROP
        iptables -P OUTPUT ACCEPT
        iptables -D INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT
        iptables -I INPUT -p tcp -m state --state NEW -m tcp --dport ${sshd_port} -j ACCEPT
        service iptables save
        service iptables restart
    fi
    count=$( ps -ef|grep '/usr/sbin/sshd'|grep -v grep|wc -l )
    if [ ${count} -eq 1 ];then
        echo "Successfully installed ${openssh_ver}!"
        ssh -V
    fi
}

echo
echo "openssl = ${openssl_ver}"
echo "openssh = ${openssh_ver}"
echo "sshd port = ${sshd_port}"
echo
read -r -p "Are you sure you want to continue? [y/n]" input
case $input in
    "y")
        yum -y install gcc wget perl make pam-devel
        install_openssl
        install_zlib
        install_openssh
        ;;
    *)
        exit 1
        ;;
esac
