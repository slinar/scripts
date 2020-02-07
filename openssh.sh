#!/bin/bash
# Recently updated: 2020/1/31 4:25

openssl_ver="openssl-1.1.1d"
openssh_ver="openssh-8.1p1"
pam="0"
sshd_port=$( netstat -lnp|grep sshd|grep -vE 'grep|unix|:::'|awk '{print $4}'|awk -F':' '{print $2}' )
[ -z "${sshd_port}" ] && sshd_port="22"

install_zlib(){
    if [ -f /usr/local/zlib-1.2.11/lib/libz.a ];then
        echo "zlib-1.2.11 already exists!"
        return
    fi
    cd /tmp || exit 1
    if [ ! -f zlib-1.2.11.tar.gz ];then
        if ! wget --tries 3 --retry-connrefused -O zlib-1.2.11.tar.gz "https://zlib.net/zlib-1.2.11.tar.gz"; then
            rm -rf zlib-1.2.11.tar.gz
            echo "zlib-1.2.11.tar.gz download failed!"
            exit 1
        fi
    fi
    tar xzf zlib-1.2.11.tar.gz || exit 1
    cd zlib-1.2.11 || exit 1
    chmod 744 configure || exit 1
    ./configure --prefix=/usr/local/zlib-1.2.11 \
    || { echo "Failed to configure zlib!";exit 1;}
    make
    make install
    local count
    count=$( grep -xc "/usr/local/zlib-1.2.11/lib" /etc/ld.so.conf )
    [ "${count}" -eq 0 ] && sed -i '$a\/usr/local/zlib-1.2.11/lib' /etc/ld.so.conf
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
    cd /tmp || exit 1
    if [ ! -f ${openssl_ver}.tar.gz ];then
        if ! wget --tries 3 --retry-connrefused -O ${openssl_ver}.tar.gz "https://www.openssl.org/source/${openssl_ver}.tar.gz";then
            rm -rf ${openssl_ver}.tar.gz
            echo "${openssl_ver}.tar.gz download failed!"
            exit 1
        fi
    fi
    tar xzf ${openssl_ver}.tar.gz || exit 1
    cd ${openssl_ver} || exit 1
    chmod 744 config || exit 1
    ./config --prefix=/usr/local/${openssl_ver} --openssldir=/usr/local/${openssl_ver}/ssl -fPIC \
    || { echo "Failed to config openssl!";exit 1;}
    make
    make install
    local count
    count=$( grep -xc "/usr/local/${openssl_ver}/lib" /etc/ld.so.conf )
    [ "${count}" -eq 0 ] && sed -i '$a\/usr/local/'${openssl_ver}'/lib' /etc/ld.so.conf
    ldconfig
    rm -rf /usr/local/${openssl_ver}/ssl/certs
    ln -s /etc/pki/tls/certs /usr/local/${openssl_ver}/ssl/certs
    ln -s /etc/pki/tls/certs/ca-bundle.crt /usr/local/${openssl_ver}/ssl/cert.pem
}

modify_iptables(){
    local num
    num=$( iptables -nvL|grep -E 'ACCEPT.*tcp.*dpt:'${sshd_port}''|grep -vc grep )
    [ "${num}" -eq 0 ] && num=$( iptables -nvL|grep -E 'ACCEPT.*tcp.*dports.* '${sshd_port}','|grep -vc grep )
    [ "${num}" -eq 0 ] && num=$( iptables -nvL|grep -E 'ACCEPT.*tcp.*dports.*,'${sshd_port}','|grep -vc grep )
    [ "${num}" -eq 0 ] && num=$( iptables -nvL|grep -E 'ACCEPT.*tcp.*dports.*,'${sshd_port}' '|grep -vc grep )
    if [ "${num}" -eq 0 ];then
        iptables -P INPUT DROP
        iptables -P FORWARD DROP
        iptables -P OUTPUT ACCEPT
        iptables -I INPUT -p tcp -m tcp --dport ${sshd_port} -j ACCEPT
        service iptables save
        service iptables restart
    fi
}

privsep(){
    if [ ! -d /var/empty/sshd ];then
        mkdir /var/empty/sshd || exit 1
    fi
    chown root:sys /var/empty/sshd
    chmod 755 /var/empty/sshd
    gid=$( grep 'sshd:x:' /etc/passwd|awk -F : '{print $4}' )
    if [ -n "${gid}" ];then
        gname=$( grep "${gid}" /etc/group|awk -F : '{print $1}' )
        [ "${gname}" != "sshd" ] && echo "user:sshd does not belong to group:sshd!" && exit 1
    else
        groupadd sshd
        useradd -g sshd -c 'sshd privsep' -d /var/empty/sshd -s /sbin/nologin sshd
    fi
}

modify_sshd_pam(){
    [ ${pam} == "0" ] && rm -f /etc/pam.d/sshd && return
    cat > /etc/pam.d/sshd<<EOF
#%PAM-1.0
auth	   required	pam_sepermit.so
auth       include      password-auth
account    required     pam_nologin.so
account    include      password-auth
password   include      password-auth
# pam_selinux.so close should be the first session rule
session    required     pam_selinux.so close
session    required     pam_loginuid.so
# pam_selinux.so open should only be followed by sessions to be executed in the user context
session    required     pam_selinux.so open env_params
session    required     pam_namespace.so
session    optional     pam_keyinit.so force revoke
session    include      password-auth
EOF
    chown root:root /etc/pam.d/sshd
    chmod 644 /etc/pam.d/sshd
}

modify_sshdconfig(){
    sed -i 's/#Port 22/Port '${sshd_port}'/' /etc/ssh/sshd_config
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
    sed -i 's/#UseDNS no/UseDNS no/' /etc/ssh/sshd_config
    [ ${pam} == "1" ] && sed -i 's/#UsePAM no/UsePAM yes/' /etc/ssh/sshd_config
    sed -i 's/#TCPKeepAlive yes/TCPKeepAlive yes/' /etc/ssh/sshd_config
    sed -i 's/#ClientAliveInterval 0/ClientAliveInterval 60/' /etc/ssh/sshd_config
}

modify_selinux(){
    sed -i 's/SELINUX=enforcing/SELINUX=disabled/' /etc/selinux/config
    setenforce 0
}

modify_permissions(){
    chown root:root /etc/rc.d/init.d/sshd
    chown root:root /etc/ssh/ssh_host_rsa_key
    chown root:root /etc/ssh/ssh_host_ecdsa_key
    chown root:root /etc/ssh/ssh_host_ed25519_key
    chown root:root /etc/ssh/ssh_host_dsa_key
    chmod 755 /etc/rc.d/init.d/sshd
    chmod 600 /etc/ssh/ssh_host_rsa_key
    chmod 600 /etc/ssh/ssh_host_ecdsa_key
    chmod 600 /etc/ssh/ssh_host_ed25519_key
    chmod 600 /etc/ssh/ssh_host_dsa_key
}

uninstall_old_openssh(){
    cp -f /etc/pam.d/sshd /etc/pam.d/sshd_bak >/dev/null 2>&1
    git --version >/dev/null 2>&1
    [ $? -eq 127 ] && yum -y remove openssh
    yum -y remove openssh-server
    chkconfig --del sshd
    rm -f /etc/ssh/moduli
    rm -f /etc/ssh/ssh_config
    rm -f /etc/ssh/sshd_config
    rm -f /etc/rc.d/init.d/sshd
}

download_openssh(){
    if [ ! -f ${openssh_ver}.tar.gz ];then
        if ! wget --tries 3 --retry-connrefused -O ${openssh_ver}.tar.gz "https://cloudflare.cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/${openssh_ver}.tar.gz";then
            rm -rf ${openssh_ver}.tar.gz
            echo "${openssh_ver}.tar.gz download failed!"
            exit 1
        fi
    fi
    tar xzf ${openssh_ver}.tar.gz || { echo "tar xzf ${openssh_ver}.tar.gz failed!";exit 1;}
    cd ${openssh_ver} || { echo "cd ${openssh_ver} failed!";exit 1;}
    chmod 744 configure || { echo "chmod 744 configure failed!";exit 1;}
}

install_openssh(){
    cd /tmp || exit 1
    download_openssh
    privsep
    if [ ${pam} == "0" ];then
        ./configure --prefix=/usr --sysconfdir=/etc/ssh --with-ssl-dir=/usr/local/${openssl_ver} --with-zlib=/usr/local/zlib-1.2.11 --with-md5-passwords --with-privsep-path=/var/empty/sshd --with-privsep-user=sshd \
        || { echo "Failed to configure openssh!";exit 1;}
    elif [ ${pam} == "1" ];then
        ./configure --prefix=/usr --sysconfdir=/etc/ssh --with-ssl-dir=/usr/local/${openssl_ver} --with-zlib=/usr/local/zlib-1.2.11 --with-md5-passwords --with-pam --with-privsep-path=/var/empty/sshd --with-privsep-user=sshd \
        || { echo "Failed to configure openssh!";exit 1;}
    else
        echo 'pam value error! 0 or 1'
        exit 1
    fi
    make || { echo "Failed to make openssh!";exit 1;}
    trap "" 2
    uninstall_old_openssh
    make install
    cp -f /tmp/${openssh_ver}/contrib/redhat/sshd.init /etc/rc.d/init.d/sshd
    modify_sshdconfig
    modify_iptables
    modify_sshd_pam
    modify_selinux
    modify_permissions
    chkconfig --add sshd
    chkconfig sshd on
    local sshd_pid
    sshd_pid=$( pgrep -of '^/usr/sbin/sshd$' )
    if [ -z "${sshd_pid}" ];then
        service sshd start
    else
        service sshd restart
    fi
    sshd_pid=$( pgrep -of '^/usr/sbin/sshd$' )
    [ -n "${sshd_pid}" ] && echo "Successfully installed ${openssh_ver}!" && ssh -V && exit 0
}

clean_tmp(){
    rm -rf /tmp/zlib-1.2.11
    rm -rf /tmp/${openssl_ver}
    rm -rf /tmp/${openssh_ver}
}

echo
echo "openssl = ${openssl_ver}"
echo "openssh = ${openssh_ver}"
echo "sshd port = ${sshd_port}"
echo "pam = ${pam}"
echo "Backup: /etc/pam.d/sshd /etc/pam.d/sshd_bak"
echo
read -r -n 1 -p "Are you sure you want to continue? [y/n]" input
case $input in
    "y")
        yum -y install gcc wget perl make pam-devel
        clean_tmp
        install_openssl
        install_zlib
        install_openssh
        ;;
    *)
        echo
        exit 1
        ;;
esac
