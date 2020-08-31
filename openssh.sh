#!/bin/bash

openssh_ver="openssh-8.3p1"
libressl_ver="libressl-3.1.4"

# Use default sshd_config
new_config=yes

# Enables PAM support
pam=no

# Do not use openssl(libressl)
without_openssl=no

sshd_port=$( netstat -lnp|grep sshd|grep -vE 'unix|:::'|awk '{print $4}'|awk -F':' '{print $2}' )
[ -z "${sshd_port}" ] && sshd_port="22"
export CFLAGS=-fPIC
if [[ ${new_config} != yes && ${new_config} != no ]]; then
    echo "new_config=yes or new_config=no"
    exit 1
fi
if [[ ${without_openssl} != yes && ${without_openssl} != no ]]; then
    echo "without_openssl=yes or without_openssl=no"
    exit 1
fi

build_zlib(){
    cd /tmp || exit 1
    if [ ! -f zlib-1.2.11.tar.gz ];then
        if ! wget --continue --timeout=6 --tries=3 --retry-connrefused -O zlib-1.2.11.tar.gz "https://zlib.net/zlib-1.2.11.tar.gz"; then
            rm -f zlib-1.2.11.tar.gz
            wget --continue --timeout=6 --tries=3 --retry-connrefused -O zlib-1.2.11.tar.gz "https://pan.0db.org/directlink/1/dep/zlib-1.2.11.tar.gz" \
            || { rm -f zlib-1.2.11.tar.gz; echo "zlib-1.2.11.tar.gz download failed"; exit 1;}
        fi
    fi
    tar xzf zlib-1.2.11.tar.gz || { rm -f zlib-1.2.11.tar.gz; exit 1;}
    cd zlib-1.2.11 || exit 1
    chmod 744 configure || exit 1
    ./configure --prefix=/tmp/${openssh_ver}/zlib --static \
    || { echo "Failed to configure zlib";exit 1;}
    make && make install
}

build_libressl(){
    [ ${without_openssl} == yes ] && return
    cd /tmp || exit 1
    if [ ! -f ${libressl_ver}.tar.gz ]; then
        if ! wget --continue --timeout=6 --tries=3 --retry-connrefused -O ${libressl_ver}.tar.gz "https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/${libressl_ver}.tar.gz"; then
            rm -f ${libressl_ver}.tar.gz
            wget --continue --timeout=6 --tries=3 --retry-connrefused -O ${libressl_ver}.tar.gz "https://pan.0db.org/directlink/1/dep/${libressl_ver}.tar.gz" \
            || { rm -f ${libressl_ver}.tar.gz; echo "${libressl_ver}.tar.gz download failed"; exit 1;}
        fi
    fi
    tar xzf ${libressl_ver}.tar.gz || { rm -f ${libressl_ver}.tar.gz; exit 1;}
    cd ${libressl_ver} || exit 1
    chmod 744 configure || exit 1
    ./configure --prefix=/tmp/${openssh_ver}/libressl --includedir=/usr/include --enable-shared=no --disable-tests \
    || { echo "Failed to config libressl";exit 1;}
    make && make install && return
    echo "make or make install libressl failed"
    exit 1
}

modify_iptables(){
    local num
    num=$( iptables -nvL|grep -cE 'ACCEPT.*tcp.*dpt:'${sshd_port}'' )
    [ "${num}" -eq 0 ] && num=$( iptables -nvL|grep -cE 'ACCEPT.*tcp.*dports.* '${sshd_port}',' )
    [ "${num}" -eq 0 ] && num=$( iptables -nvL|grep -cE 'ACCEPT.*tcp.*dports.*,'${sshd_port}',' )
    [ "${num}" -eq 0 ] && num=$( iptables -nvL|grep -cE 'ACCEPT.*tcp.*dports.*,'${sshd_port}' ' )
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
        [ "${gname}" != "sshd" ] && echo "user:sshd does not belong to group:sshd" && exit 1
    else
        groupadd sshd
        useradd -g sshd -c 'sshd privsep' -d /var/empty/sshd -s /sbin/nologin sshd
    fi
}

modify_sshd_pam(){
    [ ${pam} == no ] && rm -f /etc/pam.d/sshd && return
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
    [ ${pam} == yes ] && sed -i 's/#UsePAM no/UsePAM yes/' /etc/ssh/sshd_config
    sed -i 's/#TCPKeepAlive yes/TCPKeepAlive yes/' /etc/ssh/sshd_config
    sed -i 's/#ClientAliveInterval 0/ClientAliveInterval 60/' /etc/ssh/sshd_config
}

modify_selinux(){
    sed -i 's/SELINUX=enforcing/SELINUX=disabled/' /etc/selinux/config
    setenforce 0
}

modify_permissions(){
    rm -f /etc/ssh/ssh_host_*
    /usr/bin/ssh-keygen -A
    [ ! -f /etc/ssh/ssh_host_rsa_key.pub ] && touch /etc/ssh/ssh_host_rsa_key.pub
    [ ! -f /etc/ssh/ssh_host_dsa_key.pub ] && touch /etc/ssh/ssh_host_dsa_key.pub
    [ ! -f /etc/ssh/ssh_host_ecdsa_key.pub ] && touch /etc/ssh/ssh_host_ecdsa_key.pub
    chown root:root /etc/rc.d/init.d/sshd
    chmod 755 /etc/rc.d/init.d/sshd
}

uninstall_old_openssh(){
    cp -f /etc/pam.d/sshd /etc/pam.d/sshd_bak > /dev/null 2>&1
    mv -f /etc/ssh/ssh_config /etc/ssh/ssh_config_bak > /dev/null 2>&1
    mv -f /etc/ssh/sshd_config /etc/ssh/sshd_config_bak > /dev/null 2>&1
    rpm -e --test openssh-clients && yum -y remove openssh-clients
    yum -y remove openssh-server
    rpm -e --test openssh && yum -y remove openssh
    chkconfig --del sshd > /dev/null 2>&1
    rm -f /etc/ssh/moduli
    rm -f /etc/rc.d/init.d/sshd
}

download_openssh(){
    if [ ! -f ${openssh_ver}.tar.gz ];then
        if ! wget --continue --timeout=6 --tries=3 --retry-connrefused -O ${openssh_ver}.tar.gz "https://cloudflare.cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/${openssh_ver}.tar.gz";then
            rm -f ${openssh_ver}.tar.gz
            echo "${openssh_ver}.tar.gz download failed"
            exit 1
        fi
    fi
    tar xzf ${openssh_ver}.tar.gz || { echo "tar xzf ${openssh_ver}.tar.gz failed";rm -f ${openssh_ver}.tar.gz;exit 1;}
    cd ${openssh_ver} || exit 1
    chmod 744 configure || exit 1
}

install_openssh(){
    cd /tmp || exit 1
    download_openssh
    privsep
    local pam_option
    local libressl_option
    [ ${pam} == yes ] && pam_option='--with-pam'
    [ ${without_openssl} == yes ] && libressl_option='--without-openssl'
    [ ${without_openssl} == no ] && libressl_option='--with-ssl-dir=libressl'
    unset CFLAGS
    ./configure --prefix=/usr --sysconfdir=/etc/ssh ${libressl_option} ${pam_option} --with-zlib=zlib --with-cflags=-fPIC --with-privsep-path=/var/empty/sshd --with-privsep-user=sshd \
    || { echo "Failed to configure openssh";exit 1;}
    make || { echo "Failed to make openssh";exit 1;}
    trap "" 2
    uninstall_old_openssh
    make install
    cp -f /tmp/${openssh_ver}/contrib/redhat/sshd.init /etc/rc.d/init.d/sshd
    if [ ${new_config} == no ]; then
        echo "mod config_bak"
        [ ${pam} == no ] && sed -i 's/UsePAM yes/#UsePAM no/' /etc/ssh/sshd_config_bak >/dev/null 2>&1
        [ ${pam} == yes ] && sed -i 's/#UsePAM no/UsePAM yes/' /etc/ssh/sshd_config_bak >/dev/null 2>&1
        [ ${pam} == yes ] && sed -i 's/UsePAM no/UsePAM yes/' /etc/ssh/sshd_config_bak >/dev/null 2>&1
        if /usr/sbin/sshd -t -f /etc/ssh/sshd_config_bak; then
            echo "old config"
            rm -f /etc/ssh/sshd_config
            rm -f /etc/ssh/ssh_config
            mv -f /etc/ssh/sshd_config_bak /etc/ssh/sshd_config
            mv -f /etc/ssh/ssh_config_bak /etc/ssh/ssh_config
        else
            echo "new config"
            rm -f /etc/ssh/sshd_config_bak
            rm -f /etc/ssh/ssh_config_bak
            modify_sshdconfig
        fi
    elif [ ${new_config} == yes ]; then
        echo "new config"
        rm -f /etc/ssh/sshd_config_bak
        rm -f /etc/ssh/ssh_config_bak
        modify_sshdconfig
    fi
    modify_iptables
    modify_sshd_pam
    modify_selinux
    modify_permissions
    chkconfig --add sshd
    chkconfig sshd on
    local sshd_pid
    sshd_pid=$(pgrep -ofP "$(cat /proc/sys/kernel/core_uses_pid)" /usr/sbin/sshd)
    [ -n "${sshd_pid}" ] && kill -TERM "${sshd_pid}"
    rm -f /var/run/sshd.pid
    rm -f /var/lock/subsys/sshd
    service sshd start
    service sshd status && ssh -V && echo "Completed" && exit 0
}

clean_tmp(){
    rm -rf /tmp/zlib-1.2.11
    rm -rf /tmp/${libressl_ver}
    rm -rf /tmp/${openssh_ver}
}

echo "-------------------------------------------"
echo "libressl        : ${libressl_ver}"
echo "openssh         : ${openssh_ver}"
echo "sshd_port       : ${sshd_port}"
echo "pam             : ${pam}"
echo "new_config      : ${new_config}"
echo "without_openssl : ${without_openssl}"
echo "Backup     : /etc/pam.d/sshd /etc/pam.d/sshd_bak"
[ ${without_openssl} == yes ] && echo "[Warning] Your ssh client(SecureCRT >= 8.5.2) must support the following key exchange algorithms:" && printf "\tcurve25519-sha256\n\tcurve25519-sha256@libssh.org\n"
echo "-------------------------------------------"
read -r -n 1 -p "Are you sure you want to continue? [y/n]" input
case $input in
    "y")
        echo
        yum -y install gcc wget perl make pam-devel
        clean_tmp
        build_libressl
        build_zlib
        install_openssh
        ;;
    *)
        echo
        exit 1
        ;;
esac
