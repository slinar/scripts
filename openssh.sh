#!/bin/bash

openssh_ver="openssh-8.4p1"
libressl_ver="libressl-3.2.3"

# Use default sshd_config. If you want to use your sshd_config, please set this to "no"
new_config=yes

# Enables PAM support
pam=no

# Do not use openssl(libressl)
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
        ver=$(awk '{print $4}' /etc/redhat-release|awk -F . '{print $1}')
        if [[ "${ver}" == 7 || "${ver}" == 8 ]]; then
            echo -n "${ver}"
            return
        fi
    fi
    echo "This linux distribution is not supported"
    exit 1
}

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
    yum makecache || return
    cd /etc/yum.repos.d || exit 1
    mv -f /etc/yum.repos.d/CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo.bak
    _download "https://el.0db.org/6/CentOS-Base.repo" || exit 1
    yum clean && yum makecahce && return
    exit 1
}

build_zlib(){
    cd /tmp || exit 1
    declare -a url=(
        "https://zlib.net/zlib-1.2.11.tar.gz"
        "https://pan.0db.org/directlink/1/dep/zlib-1.2.11.tar.gz"
    )
    { _download "${url[@]}" && tar -zxf zlib-1.2.11.tar.gz && cd zlib-1.2.11 && chmod 744 configure;} || exit 1
    ./configure --prefix=/tmp/${openssh_ver}/zlib --static \
    || { echo "Failed to configure zlib";exit 1;}
    make && make install && return
    exit 1
}

build_libressl(){
    [ ${without_openssl} == yes ] && return
    cd /tmp || exit 1
    declare -a url=(
        "https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/${libressl_ver}.tar.gz"
        "https://pan.0db.org/directlink/1/dep/${libressl_ver}.tar.gz"
    )
    { _download "${url[@]}" && tar -zxf ${libressl_ver}.tar.gz && cd ${libressl_ver} && chmod 744 configure;} || exit 1
    ./configure --prefix=/tmp/${openssh_ver}/libressl --includedir=/usr/include --enable-shared=no --disable-tests \
    || { echo "Failed to config libressl";exit 1;}
    make && make install && return
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

privsep(){
    local gid
    local gname
    mkdir -p /var/empty/sshd
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
    rm -f /etc/ssh/ssh_host_*
    /usr/bin/ssh-keygen -A
    [ ! -f /etc/ssh/ssh_host_rsa_key.pub ] && touch /etc/ssh/ssh_host_rsa_key.pub
    [ ! -f /etc/ssh/ssh_host_dsa_key.pub ] && touch /etc/ssh/ssh_host_dsa_key.pub
    [ ! -f /etc/ssh/ssh_host_ecdsa_key.pub ] && touch /etc/ssh/ssh_host_ecdsa_key.pub
}

sshd_init(){
    case "$1" in
        "install")
            cp -f /tmp/${openssh_ver}/contrib/redhat/sshd.init /etc/rc.d/init.d/sshd
            chkconfig --add sshd
            chkconfig sshd on
            chown root:root /etc/rc.d/init.d/sshd
            chmod 755 /etc/rc.d/init.d/sshd
            ;;
        "uninstall")
            chkconfig --del sshd > /dev/null 2>&1
            rm -f /etc/ssh/moduli
            rm -f /etc/rc.d/init.d/sshd
            echo
            ;;
        "status")
            service sshd status
            ;;
        "start")
            service sshd start
            ;;
        "stop")
            service sshd stop
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
    local libressl_option
    [ ${pam} == yes ] && pam_option='--with-pam'
    [ ${without_openssl} == yes ] && libressl_option='--without-openssl'
    [ ${without_openssl} == no ] && libressl_option='--with-ssl-dir=libressl'
    ./configure --prefix=/usr --sysconfdir=/etc/ssh ${libressl_option} ${pam_option} --with-zlib=zlib --with-cflags=-fPIC --with-privsep-path=/var/empty/sshd --with-privsep-user=sshd \
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
    modify_iptables
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
    rm -rf /tmp/${libressl_ver}
    rm -rf /tmp/${openssh_ver}
}

_checkPrivilege
os_ver=$(_sysVer)
if [[ "${os_ver}" == 7 || "${os_ver}" == 8 ]]; then
    yum -y install net-tools >/dev/null
fi
sshd_port=$( netstat -lnp|grep sshd|grep -vE 'unix|:::'|awk '{print $4}'|awk -F':' '{print $2}' )
[ -z "${sshd_port}" ] && sshd_port="22"
export CFLAGS="-fPIC"
export CXXFLAGS="-fPIC"

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
        check_yum
        yum -y install gcc wget perl make pam-devel || exit 1
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
