#!/bin/bash

openssh_ver="openssh-8.4p1"
openssl_ver="openssl-1.1.1i"

# Use default sshd_config. If you want to use your sshd_config, please set this to "no"
new_config=yes

# Enables PAM support
pam=no

# Do not use openssl
without_openssl=no

[[ "${new_config}" =~ yes|no ]] || { echo "The value of new_config is invalid";exit 1;}
[[ "${pam}" =~ yes|no ]] || { echo "The value of pam is invalid";exit 1;}
[[ "${without_openssl}" =~ yes|no ]] || { echo "The value of without_openssl is invalid";exit 1;}

_checkPrivilege(){
    touch /etc/checkPrivilege >/dev/null 2>&1 && rm -f /etc/checkPrivilege && return 0
    echo "require root privileges"
    exit 1
}

_sysVer(){
    local ver
    ver=$(awk '{print $3}' /etc/redhat-release|awk -F . '{print $1}')
    if [ "${ver}" == 6 ]; then
        echo -n "${ver}"
        return
    else
        export SYSTEMD_PAGER=cat
        ver=$(awk '{print $4}' /etc/redhat-release|awk -F . '{print $1}')
        if [[ "${ver}" == 7 || "${ver}" == 8 ]]; then
            echo -n "${ver}"
            return
        fi
    fi
    echo "This linux distribution is not supported"
    exit 1
}

os_ver=$(_sysVer)

_download(){
    local url
    local fileName
    local tarFileName
    local tarOptions
    declare -r urlReg='^(http|https|ftp)://[a-zA-Z0-9\.-]{1,62}\.[a-zA-Z]{1,62}(:[0-9]{1,5})?/.*'
    declare -r Reg='(\.tar\.gz|\.tgz|\.tar\.bz2|\.tar\.xz)$'
    tar --version >/dev/null 2>&1 || yum -y install tar || exit 1
    xz --version >/dev/null 2>&1 || yum -y install xz || exit 1
    for url in "$@"; do
        if [[ ${url} =~ ${urlReg} ]]; then
            fileName=$(echo "${url}"|awk -F / '{print $NF}')
            if [[ "${fileName}" =~ ${Reg} ]]; then
                tarOptions='-axf'
                tarFileName=${fileName}
            else
                tarOptions='--version'
                tarFileName=''
            fi
            if [ -f "${fileName}" ]; then
                tar ${tarOptions} "${tarFileName}" -O >/dev/null && return 0
                rm -f "${fileName}"
            fi
            wget --continue --timeout=10 --tries=3 --retry-connrefused -O "${fileName}" "${url}" && tar ${tarOptions} "${tarFileName}" -O >/dev/null && return 0
            rm -f "${fileName}"
        fi
    done
    return 1
}

check_yum(){
    local ver
    ver=$(_sysVer)
    [ "${ver}" -ne 6 ] && return
    [ -f /etc/yum.repos.d/CentOS-Base.repo ] && yum makecache && return
    mv -f /etc/yum.repos.d/CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo.bak >/dev/null 2>&1
    curl --silent -L "https://pan.0db.org/directlink/1/Centos/CentOS-Base.repo" -o /etc/yum.repos.d/CentOS-Base.repo || exit 1
    yum clean all && yum makecache && return
    exit 1
}

build_zlib(){
    cd /tmp || exit 1
    declare -a url=(
        "https://zlib.net/zlib-1.2.11.tar.gz"
        "https://pan.0db.org/directlink/1/dep/zlib-1.2.11.tar.gz"
    )
    { _download "${url[@]}" && tar -zxf zlib-1.2.11.tar.gz && cd zlib-1.2.11 && chmod 744 configure;} || exit 1
    export CFLAGS="-fPIC"
    ./configure --prefix=/tmp/${openssh_ver}/zlib --static \
    || { echo "Failed to configure zlib";exit 1;}
    make && make install && unset CFLAGS && return
    exit 1
}

build_openssl(){
    [ ${without_openssl} == yes ] && return
    cd /tmp || exit 1
    declare -a url=(
        "https://www.openssl.org/source/${openssl_ver}.tar.gz"
        "https://pan.0db.org/directlink/1/dep/${openssl_ver}.tar.gz"
    )
    { _download "${url[@]}" && tar -zxf ${openssl_ver}.tar.gz && cd ${openssl_ver} && chmod 744 config;} || exit 1
    ./config --prefix=/tmp/${openssh_ver}/openssl --openssldir=/tmp/${openssh_ver}/openssl/ssl -fPIC no-shared no-threads \
    || { echo "Failed to config openssl";exit 1;}
    make && make install_sw && return
    exit 1
}

modify_iptables(){
    local num
    num=$( iptables -nvL|grep -cE "ACCEPT.*tcp.*dpt:${sshd_port}" )
    [ "${num}" -eq 0 ] && num=$( iptables -nvL|grep -cE "ACCEPT.*tcp.*dports.* ${sshd_port}," )
    [ "${num}" -eq 0 ] && num=$( iptables -nvL|grep -cE "ACCEPT.*tcp.*dports.*,${sshd_port}," )
    [ "${num}" -eq 0 ] && num=$( iptables -nvL|grep -cE "ACCEPT.*tcp.*dports.*,${sshd_port} " )
    if [ "${num}" -eq 0 ];then
        iptables -P INPUT DROP
        iptables -P FORWARD DROP
        iptables -P OUTPUT ACCEPT
        iptables -I INPUT -p tcp -m tcp --dport "${sshd_port}" -j ACCEPT
        service iptables save
        service iptables restart
    fi
}

modify_firewalld(){
    firewall-cmd --query-port "${sshd_port}"/tcp && return
    firewall-cmd --add-port="${sshd_port}"/tcp --permanent && firewall-cmd --reload
}

modify_fw(){
    if [ "${os_ver}" == 6 ]; then
        modify_iptables
    elif systemctl status firewalld.service; then
        modify_firewalld
    elif systemctl status iptables.service; then
        modify_iptables
    fi
}

systemd_sshd(){
    cat > /usr/lib/systemd/system/sshd.service<<EOF
[Unit]
Description=OpenSSH server daemon
Documentation=man:sshd(8) man:sshd_config(5)
After=network.target sshd-keygen.target
Wants=sshd-keygen.target

[Service]
Type=simple
EnvironmentFile=-/etc/crypto-policies/back-ends/opensshserver.config
EnvironmentFile=-/etc/sysconfig/sshd
ExecStart=/usr/sbin/sshd -D $OPTIONS $CRYPTO_POLICY
ExecReload=/bin/kill -HUP $MAINPID
KillMode=process
Restart=on-failure
RestartSec=42s

[Install]
WantedBy=multi-user.target
EOF

    cat > /usr/lib/systemd/system/sshd@.service<<EOF
[Unit]
Description=OpenSSH per-connection server daemon
Documentation=man:sshd(8) man:sshd_config(5)
Wants=sshd-keygen.target
After=sshd-keygen.target

[Service]
EnvironmentFile=-/etc/crypto-policies/back-ends/opensshserver.config
EnvironmentFile=-/etc/sysconfig/sshd
ExecStart=-/usr/sbin/sshd -i $OPTIONS $CRYPTO_POLICY
StandardInput=socket
EOF

    cat > /usr/lib/systemd/system/sshd.socket<<EOF
[Unit]
Description=OpenSSH Server Socket
Documentation=man:sshd(8) man:sshd_config(5)
Conflicts=sshd.service

[Socket]
ListenStream=22
Accept=yes

[Install]
WantedBy=sockets.target
EOF

    cat > /usr/lib/systemd/system/sshd-keygen.target<<EOF
[Unit]
Wants=sshd-keygen@rsa.service
Wants=sshd-keygen@ecdsa.service
Wants=sshd-keygen@ed25519.service
PartOf=sshd.service
EOF

    cat > /usr/lib/systemd/system/sshd-keygen@.service<<EOF
[Unit]
Description=OpenSSH %i Server Key Generation
ConditionFileNotEmpty=|!/etc/ssh/ssh_host_%i_key

[Service]
Type=oneshot
EnvironmentFile=-/etc/sysconfig/sshd
ExecStart=/usr/libexec/openssh/sshd-keygen %i

[Install]
WantedBy=sshd-keygen.target
EOF

    cat > /etc/sysconfig/sshd<<EOF
# Do not change this option unless you have hardware random
# generator and you REALLY know what you are doing
SSH_USE_STRONG_RNG=0

# System-wide crypto policy:
# To opt-out, uncomment the following line
# CRYPTO_POLICY=
EOF

    if [ "${os_ver}" == 8 ]; then
        cat > /usr/share/crypto-policies/DEFAULT/opensshserver.txt<<EOF
CRYPTO_POLICY='-oCiphers=aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr,aes256-cbc,aes128-gcm@openssh.com,aes128-ctr,aes128-cbc -oMACs=hmac-sha2-256-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha1,umac-128@openssh.com,hmac-sha2-512 -oGSSAPIKexAlgorithms=gss-gex-sha1-,gss-group14-sha1- -oKexAlgorithms=curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1 -oHostKeyAlgorithms=rsa-sha2-256,rsa-sha2-256-cert-v01@openssh.com,ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384,ecdsa-sha2-nistp384-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-512-cert-v01@openssh.com,ecdsa-sha2-nistp521,ecdsa-sha2-nistp521-cert-v01@openssh.com,ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,ssh-rsa,ssh-rsa-cert-v01@openssh.com -oPubkeyAcceptedKeyTypes=rsa-sha2-256,rsa-sha2-256-cert-v01@openssh.com,ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384,ecdsa-sha2-nistp384-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-512-cert-v01@openssh.com,ecdsa-sha2-nistp521,ecdsa-sha2-nistp521-cert-v01@openssh.com,ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,ssh-rsa,ssh-rsa-cert-v01@openssh.com -oCASignatureAlgorithms=rsa-sha2-256,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,rsa-sha2-512,ecdsa-sha2-nistp521,ssh-ed25519,ssh-rsa'
EOF
        chown root:root /usr/share/crypto-policies/DEFAULT/opensshserver.txt
        chmod 644 /usr/share/crypto-policies/DEFAULT/opensshserver.txt
        ln -sf /usr/share/crypto-policies/DEFAULT/opensshserver.txt /etc/crypto-policies/back-ends/opensshserver.config
        cat > /usr/share/crypto-policies/DEFAULT/openssh.txt<<EOF
Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr,aes256-cbc,aes128-gcm@openssh.com,aes128-ctr,aes128-cbc
MACs hmac-sha2-256-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha1,umac-128@openssh.com,hmac-sha2-512
GSSAPIKexAlgorithms gss-gex-sha1-,gss-group14-sha1-
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1
PubkeyAcceptedKeyTypes rsa-sha2-256,rsa-sha2-256-cert-v01@openssh.com,ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384,ecdsa-sha2-nistp384-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-512-cert-v01@openssh.com,ecdsa-sha2-nistp521,ecdsa-sha2-nistp521-cert-v01@openssh.com,ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,ssh-rsa,ssh-rsa-cert-v01@openssh.com
CASignatureAlgorithms rsa-sha2-256,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,rsa-sha2-512,ecdsa-sha2-nistp521,ssh-ed25519,ssh-rsa
EOF
        chown root:root /usr/share/crypto-policies/DEFAULT/openssh.txt
        chmod 644 /usr/share/crypto-policies/DEFAULT/openssh.txt
        ln -sf /usr/share/crypto-policies/DEFAULT/openssh.txt /etc/crypto-policies/back-ends/openssh.config
    fi

    chown root:root /usr/lib/systemd/system/sshd.service
    chmod 644 /usr/lib/systemd/system/sshd.service
    chown root:root /usr/lib/systemd/system/sshd@.service
    chmod 644 /usr/lib/systemd/system/sshd@.service
    chown root:root /usr/lib/systemd/system/sshd.socket
    chmod 644 /usr/lib/systemd/system/sshd.socket
    chown root:root /usr/lib/systemd/system/sshd-keygen.target
    chmod 644 /usr/lib/systemd/system/sshd-keygen.target
    chown root:root /usr/lib/systemd/system/sshd-keygen@.service
    chmod 644 /usr/lib/systemd/system/sshd-keygen@.service
}

privsep(){
    local gid
    local gname
    mkdir -p /var/empty/sshd
    chown root:root /var/empty/sshd
    chmod 711 /var/empty/sshd
    gid=$( grep 'sshd:x:' /etc/passwd|awk -F : '{print $4}' )
    if [ -n "${gid}" ];then
        gname=$( grep "${gid}" /etc/group|awk -F : '{print $1}' )
        [ "${gname}" != "sshd" ] && echo "user:sshd does not belong to group:sshd" && exit 1
    else
        groupadd sshd
        useradd -g sshd -c 'sshd privsep' -d /var/empty/sshd -s /sbin/nologin sshd
    fi
}

modify_sshd_pam_6(){
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
}

modify_sshd_pam_7(){
    cat > /etc/pamd.d/sshd<<EOF
#%PAM-1.0
auth       required     pam_sepermit.so
auth       substack     password-auth
auth       include      postlogin
# Used with polkit to reauthorize users in remote sessions
-auth      optional     pam_reauthorize.so prepare
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
session    include      postlogin
# Used with polkit to reauthorize users in remote sessions
-session   optional     pam_reauthorize.so prepare
EOF
}

modify_sshd_pam_8(){
    cat > /etc/pam.d/sshd<<EOF
#%PAM-1.0
auth       substack     password-auth
auth       include      postlogin
account    required     pam_sepermit.so
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
session    optional     pam_motd.so
session    include      password-auth
session    include      postlogin
EOF
}

modify_sshd_pam(){
    [ ${pam} == no ] && rm -f /etc/pam.d/sshd && return
    if [ "${os_ver}" == 6 ]; then
        modify_sshd_pam_6
    elif [ "${os_ver}" == 7 ];then
        modify_sshd_pam_7
    elif [ "${os_ver}" == 8 ];then
        modify_sshd_pam_8
    fi
    chown root:root /etc/pam.d/sshd
    chmod 644 /etc/pam.d/sshd
}

modify_sshdconfig(){
    sed -i 's/#Port 22/Port '"${sshd_port}"'/' /etc/ssh/sshd_config
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
    /usr/bin/ssh-keygen -A
    [ ! -f /etc/ssh/ssh_host_rsa_key.pub ] && touch /etc/ssh/ssh_host_rsa_key.pub
    [ ! -f /etc/ssh/ssh_host_dsa_key.pub ] && touch /etc/ssh/ssh_host_dsa_key.pub
    [ ! -f /etc/ssh/ssh_host_ecdsa_key.pub ] && touch /etc/ssh/ssh_host_ecdsa_key.pub
}

sshd_init(){
    case "$1" in
        "install")
            if [ "${os_ver}" == 6 ]; then
                cp -f /tmp/${openssh_ver}/contrib/redhat/sshd.init /etc/rc.d/init.d/sshd
                chkconfig --add sshd
                chkconfig sshd on
                chown root:root /etc/rc.d/init.d/sshd
                chmod 755 /etc/rc.d/init.d/sshd
            else
                systemd_sshd
                systemctl daemon-reload
                systemctl enable sshd.service
            fi
            ;;
        "uninstall")
            if [ "${os_ver}" == 6 ]; then
                chkconfig --del sshd > /dev/null 2>&1
                rm -f /etc/rc.d/init.d/sshd
            else
                if systemctl list-units --all --type=service|grep sshd.service >/dev/null; then
                    systemctl stop sshd.service && systemctl disable sshd.service
                fi
                rm -f /usr/lib/systemd/system/sshd*
                rm -f /etc/ssh/ssh_host_*
                rm -f /etc/crypto-policies/back-ends/openssh.config
                rm -f /etc/crypto-policies/back-ends/opensshserver.config
                rm -f /usr/share/crypto-policies/DEFAULT/openssh.txt
                rm -f /usr/share/crypto-policies/DEFAULT/opensshserver.txt
                rm -f /etc/sysconfig/sshd
            fi
            rm -f /etc/ssh/moduli
            rm -f /var/empty/sshd
            ;;
        "status")
            if [ "${os_ver}" == 6 ]; then
                service sshd status
            else
                systemctl status sshd.service
            fi
            ;;
        "start")
            if [ "${os_ver}" == 6 ]; then
                service sshd start
            else
                systemctl start sshd.service
            fi
            ;;
        "stop")
            if [ "${os_ver}" == 6 ]; then
                service sshd stop
            else
                systemctl stop sshd.service
            fi
            ;;
        *)
            echo
            ;;
    esac
}

uninstall_old_openssh(){
    cp -f /etc/pam.d/sshd /etc/pam.d/sshd_bak > /dev/null 2>&1
    mv -f /etc/ssh/ssh_config /etc/ssh/ssh_config_bak > /dev/null 2>&1
    mv -f /etc/ssh/sshd_config /etc/ssh/sshd_config_bak > /dev/null 2>&1
    rpm -e --test openssh-clients > /dev/null 2>&1 && yum -y remove openssh-clients
    yum -y remove openssh-server > /dev/null 2>&1
    rpm -e --test openssh > /dev/null 2>&1 && yum -y remove openssh
    sshd_init uninstall
}

download_openssh(){
    cd /tmp || exit 1
    declare -a url=(
        "https://cloudflare.cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/${openssh_ver}.tar.gz"
        "https://pan.0db.org/directlink/1/dep/${openssh_ver}.tar.gz"
    )
    { _download "${url[@]}" && tar -zxf ${openssh_ver}.tar.gz && cd ${openssh_ver} && chmod 744 configure;} || exit 1
}

install_openssh(){
    download_openssh
    privsep
    local pam_option
    local openssl_option
    [ ${pam} == yes ] && pam_option='--with-pam'
    [ ${without_openssl} == yes ] && openssl_option='--without-openssl'
    [ ${without_openssl} == no ] && openssl_option="--with-ssl-dir=/tmp/${openssh_ver}/openssl"
    ./configure --prefix=/usr --sysconfdir=/etc/ssh ${openssl_option} ${pam_option} --with-zlib=/tmp/${openssh_ver}/zlib --with-privsep-path=/var/empty/sshd --with-privsep-user=sshd --with-pie \
    || { echo "Failed to configure openssh";exit 1;}
    make || { echo "Failed to make openssh";exit 1;}
    trap "" 2
    uninstall_old_openssh
    make install
    if [ ${new_config} == no ]; then
        [ ${pam} == no ] && sed -i 's/^\s*UsePAM\s\+yes\s*/#UsePAM no/' /etc/ssh/sshd_config >/dev/null 2>&1
        [ ${pam} == yes ] && sed -i 's/\s*.*UsePAM\s\+no\s*/UsePAM yes/' /etc/ssh/sshd_config >/dev/null 2>&1
        if /usr/sbin/sshd -t -f /etc/ssh/sshd_config_bak; then
            echo "The old sshd_config test is successful, use the old sshd_config"
            rm -f /etc/ssh/sshd_config
            rm -f /etc/ssh/ssh_config
            mv -f /etc/ssh/sshd_config_bak /etc/ssh/sshd_config
            mv -f /etc/ssh/ssh_config_bak /etc/ssh/ssh_config
        else
            echo "The old sshd_config test failed, use the new default sshd_config"
            rm -f /etc/ssh/sshd_config_bak
            rm -f /etc/ssh/ssh_config_bak
            modify_sshdconfig
        fi
    elif [ ${new_config} == yes ]; then
        echo "Use the new default sshd_config"
        rm -f /etc/ssh/sshd_config_bak
        rm -f /etc/ssh/ssh_config_bak
        modify_sshdconfig
    fi
    modify_fw
    modify_sshd_pam
    modify_selinux
    modify_permissions
    sshd_init install
    local sshd_pid
    sshd_pid=$(pgrep -ofP "$(cat /proc/sys/kernel/core_uses_pid)" /usr/sbin/sshd)
    [ -n "${sshd_pid}" ] && kill -TERM "${sshd_pid}"
    rm -f /var/run/sshd.pid
    rm -f /var/lock/subsys/sshd
    sshd_init start && ssh -V && echo "completed" && exit 0
}

clean_tmp(){
    rm -rf /tmp/zlib-1.2.11
    rm -rf /tmp/${openssl_ver}
    rm -rf /tmp/${openssh_ver}
}

_checkPrivilege
if [[ "${os_ver}" == 7 || "${os_ver}" == 8 ]]; then
    yum -y install net-tools >/dev/null
fi
sshd_port=$( netstat -lnp|grep sshd|grep -vE 'unix|:::'|awk '{print $4}'|awk -F':' '{print $2}' )
[ -z "${sshd_port}" ] && sshd_port="22"
echo "-------------------------------------------"
echo "openssl         : ${openssl_ver}"
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
        check_yum
        yum -y install gcc wget perl make pam-devel || exit 1
        clean_tmp
        build_openssl
        build_zlib
        install_openssh
        ;;
    *)
        echo
        exit 1
        ;;
esac
