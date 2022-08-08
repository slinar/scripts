#!/bin/bash

openssh_ver="openssh-9.0p1"
openssl_ver="openssl-1.1.1q"

# Use default sshd_config. If you want to use your sshd_config, please set this to "no"
use_default_config=yes

# Enables PAM support
pam=no

# Do not use openssl?
without_openssl=no

# Download url
declare -ra openssl_url=(
    "https://www.openssl.org/source/${openssl_ver}.tar.gz"
    "https://pan.0db.org:65000/dep/${openssl_ver}.tar.gz"
)

declare -ra openssh_url=(
    "https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/${openssh_ver}.tar.gz"
    "https://pan.0db.org:65000/dep/${openssh_ver}.tar.gz"
)

declare -r el6_repo_url="https://pan.0db.org:65000/Centos/CentOS-Base.repo"

declare -a ca_url=(
    "https://pan.0db.org:65000/dep/ca-certificates-2021.2.50-60.1.el6_10.noarch.rpm"
    "https://github.com/slinar/scripts/raw/master/ca-certificates-2021.2.50-60.1.el6_10.noarch.rpm"
    "https://els6.baruwa.com/els6/ca-certificates-2021.2.50-60.1.el6_10.noarch.rpm"
)

[[ "${use_default_config}" =~ yes|no ]] || { echo "The value of use_default_config is invalid";exit 1;}
[[ "${pam}" =~ yes|no ]] || { echo "The value of pam is invalid";exit 1;}
[[ "${without_openssl}" =~ yes|no ]] || { echo "The value of without_openssl is invalid";exit 1;}

_checkPrivilege(){
    touch /etc/checkPrivilege >/dev/null 2>&1 && rm -f /etc/checkPrivilege && return 0
    echo "require root privileges"
    exit 1
}

_sysVer(){
    local v
    local vv
    v=$(uname -r|awk -F "el" '{print $2}')
    vv=${v:0:1}
    if [[ ${vv} = "8" || ${vv} = "7" || ${vv} = "6" ]]; then
        echo -n "${vv}"
        return
    fi
    exit 2
}

os_ver=$(_sysVer)

_download(){
    local url
    local fileName
    local tarFileName
    local tarOptions
    declare -r urlReg='^(http|https|ftp)://[a-zA-Z0-9\.-]{1,62}\.[a-zA-Z]{1,62}(:[0-9]{1,5})?/.*'
    declare -r Reg='(\.tar\.gz|\.tgz|\.tar\.bz2|\.tar\.xz)$'
    [ ! -x /usr/bin/xz ] && yum -y install xz
    for url in "$@"; do
        if [[ ${url} =~ ${urlReg} ]]; then
            fileName=$(echo "${url}"|awk -F / '{print $NF}')
            if [[ "${fileName}" =~ ${Reg} ]]; then
                tarOptions='-axf'
                tarFileName="${fileName}"
            else
                tarOptions='--version'
                tarFileName=''
            fi
            if [ -f "${fileName}" ]; then
                tar ${tarOptions} "${tarFileName}" -O >/dev/null && return 0
                rm -f "${fileName}"
            fi
            echo "Downloading ${fileName} from ${url}"
            curl --continue-at - --speed-limit 10240 --speed-time 5 --retry 3 --progress-bar --location "${url}" -o "${fileName}" && tar ${tarOptions} "${tarFileName}" -O >/dev/null && return 0
            rm -f "${fileName}"
        fi
    done
    return 1
}

check_yum(){
    [ "${os_ver}" != 6 ] && return
    [ -f /etc/yum.repos.d/CentOS-Base.repo ] && yum makecache && return
    mv -f /etc/yum.repos.d/CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo.bak >/dev/null 2>&1
    curl --silent -L ${el6_repo_url} -o /etc/yum.repos.d/CentOS-Base.repo || { echo "CentOS-Base.repo download failed"; exit 3;}
    yum clean all && yum makecache && return
    exit 1
}

build_openssl(){
    [ "${without_openssl}" = yes ] && return
    cd /tmp || exit 1
    { _download "${openssl_url[@]}" && tar -zxf ${openssl_ver}.tar.gz && cd ${openssl_ver} && chmod 744 config;} || exit 1
    ./config --prefix=/tmp/openssl-static --openssldir=/tmp/openssl-static/ssl -fPIC no-shared no-threads \
    || { echo "Failed to config openssl";exit 1;}
    make && make install_sw && return
    exit 1
}

modify_iptables(){
    local num
    num=$( iptables -nvL|grep -cE "ACCEPT.*tcp.*dpt:${sshd_port}" )
    [ "${num}" -eq 0 ] && num=$( iptables -nvL|grep -cE "ACCEPT.*tcp.*dports.* ${sshd_port}" )
    [ "${num}" -eq 0 ] && num=$( iptables -nvL|grep -cE "ACCEPT.*tcp.*dports.* ${sshd_port}," )
    [ "${num}" -eq 0 ] && num=$( iptables -nvL|grep -cE "ACCEPT.*tcp.*dports.*,${sshd_port}," )
    [ "${num}" -eq 0 ] && num=$( iptables -nvL|grep -cE "ACCEPT.*tcp.*dports.*,${sshd_port}" )
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
    echo -n "Check the tcp/22 port in firewalld: "
    firewall-cmd --query-port "${sshd_port}"/tcp && return
    echo "Modify firewalld: "
    firewall-cmd --add-port="${sshd_port}"/tcp --permanent && firewall-cmd --reload
}

modify_fw(){
    if [ "${os_ver}" = 6 ]; then
        echo "modify_iptables(el6)"
        modify_iptables
    elif systemctl status firewalld.service --no-pager --full; then
        echo "modify_firewalld"
        modify_firewalld
    elif systemctl status iptables.service; then
        echo "modify_iptables(el8)"
        modify_iptables
    fi
}

systemd_sshd(){
    cat > /usr/lib/systemd/system/sshd.service<<"EOF"
[Unit]
Description=OpenSSH server daemon
Documentation=man:sshd(8) man:sshd_config(5)
After=network.target sshd-keygen.target
Wants=sshd-keygen.target

[Service]
Type=simple
EnvironmentFile=-/etc/crypto-policies/back-ends/opensshserver.config
EnvironmentFile=-/etc/sysconfig/sshd
ExecStartPre=/usr/sbin/sshd -t
ExecStart=/usr/sbin/sshd -D
ExecReload=/bin/kill -HUP $MAINPID
KillMode=process
Restart=on-failure
RestartSec=42s

[Install]
WantedBy=multi-user.target
EOF

    cat > /usr/lib/systemd/system/sshd@.service<<"EOF"
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
    [ "${pam}" = no ] && rm -f /etc/pam.d/sshd && return
    if [ "${os_ver}" = 6 ]; then
        modify_sshd_pam_6
    elif [ "${os_ver}" = 7 ];then
        modify_sshd_pam_7
    elif [ "${os_ver}" = 8 ];then
        modify_sshd_pam_8
    fi
    chown root:root /etc/pam.d/sshd
    chmod 644 /etc/pam.d/sshd
}

modify_sshdconfig(){
    sed -i 's/#Port 22/Port '"${sshd_port}"'/' /etc/ssh/sshd_config
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
    sed -i 's/#UseDNS no/UseDNS no/' /etc/ssh/sshd_config
    [ "${pam}" = yes ] && sed -i 's/#UsePAM no/UsePAM yes/' /etc/ssh/sshd_config
    sed -i 's/#TCPKeepAlive yes/TCPKeepAlive yes/' /etc/ssh/sshd_config
    sed -i 's/#ClientAliveInterval 0/ClientAliveInterval 60/' /etc/ssh/sshd_config
}

modify_selinux(){
    sed -i 's/SELINUX=enforcing/SELINUX=disabled/' /etc/selinux/config
    setenforce 0
}

generate_host_key(){
    /usr/bin/ssh-keygen -A
    [ ! -f /etc/ssh/ssh_host_rsa_key.pub ] && touch /etc/ssh/ssh_host_rsa_key.pub
    [ ! -f /etc/ssh/ssh_host_dsa_key.pub ] && touch /etc/ssh/ssh_host_dsa_key.pub
    [ ! -f /etc/ssh/ssh_host_ecdsa_key.pub ] && touch /etc/ssh/ssh_host_ecdsa_key.pub
}

modify_ssh_file_permission(){
    chown root:root -R /etc/ssh
    chmod 600 /etc/ssh/ssh_host_*_key
}

sshd_init(){
    case "$1" in
        "install")
            if [ "${os_ver}" = 6 ]; then
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
            if [ "${os_ver}" = 6 ]; then
                chkconfig --del sshd > /dev/null 2>&1
                rm -f /etc/rc.d/init.d/sshd
            else
                if systemctl list-unit-files | grep sshd.service >/dev/null; then
                    systemctl stop sshd.service && systemctl disable sshd.service
                fi
                rm -f /usr/lib/systemd/system/sshd*
                rm -f /etc/sysconfig/sshd
            fi
            rm -f /etc/ssh/ssh_host_*
            rm -f /etc/ssh/moduli
            rm -rf /var/empty/sshd
            ;;
        "status")
            if [ "${os_ver}" = 6 ]; then
                service sshd status
            else
                systemctl status sshd.service --no-pager --full
            fi
            ;;
        "start")
            if [ "${os_ver}" = 6 ]; then
                service sshd start
            else
                systemctl start sshd.service
            fi
            ;;
        "stop")
            if [ "${os_ver}" = 6 ]; then
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
    { _download "${openssh_url[@]}" && tar -zxf ${openssh_ver}.tar.gz && cd ${openssh_ver} && chmod 744 configure;} || exit 1
}

kill_sshd_main_process(){
    local sshd_pid
    sshd_pid=$(pgrep -ofP "$(cat /proc/sys/kernel/core_uses_pid)" /usr/sbin/sshd)
    [ -n "${sshd_pid}" ] && kill -TERM "${sshd_pid}"
    rm -f /var/run/sshd.pid
    rm -f /run/sshd.pid
    rm -f /var/lock/subsys/sshd
}

conf_openssh(){
    local pam_option
    local openssl_option
    [ "${pam}" = yes ] && pam_option='--with-pam'
    [ "${without_openssl}" = yes ] && openssl_option='--without-openssl'
    [ "${without_openssl}" = no ] && openssl_option="--with-ssl-dir=/tmp/openssl-static"
    ./configure --prefix=/usr --sysconfdir=/etc/ssh ${openssl_option} ${pam_option} --with-privsep-path=/var/empty/sshd --with-privsep-user=sshd --without-zlib --with-pie \
    || { echo "Failed to configure openssh";exit 1;}
}

select_config(){
    if [ "${use_default_config}" = no ] && /usr/sbin/sshd -t -f /etc/ssh/sshd_config_bak; then
        echo "The old sshd_config test is successful, use the old sshd_config"
        rm -f /etc/ssh/sshd_config
        rm -f /etc/ssh/ssh_config
        mv -f /etc/ssh/sshd_config_bak /etc/ssh/sshd_config
        mv -f /etc/ssh/ssh_config_bak /etc/ssh/ssh_config
    else
        echo "Use the new default sshd_config"
        modify_sshdconfig
    fi
}

install_openssh(){
    download_openssh
    privsep
    conf_openssh
    make || { echo "Failed to make openssh";exit 1;}
    trap "" 2
    uninstall_old_openssh
    make install
    select_config
    modify_fw
    modify_sshd_pam
    modify_selinux
    generate_host_key
    modify_ssh_file_permission
    sshd_init install
    kill_sshd_main_process
    sshd_init start && ssh -V && echo "completed" && exit 0
}

clean_tmp(){
    rm -rf /tmp/${openssl_ver}
    rm -rf /tmp/${openssh_ver}
    rm -rf /tmp/openssl-static
    if [[ ${os_ver} = "7" || ${os_ver} = "8" ]]; then
        rm -rf /run/log/journal/*
        systemctl restart systemd-journald
    fi
}

check_ca_rpm_hash(){
    local sha256
    local v
    sha256='20a5c2f415a8c873bb759aefa721446452761627789927d997c305472a959c35'
    v=$(sha256sum /tmp/ca-certificates-2021.2.50-60.1.el6_10.noarch.rpm|awk '{print $1}')
    if [ "${sha256}" = "${v}" ]; then
        return 0
    else
        echo "sha256 error: ${v}"
        return 1
    fi
}

check_ca_file_hash(){
    local sha256
    local v
    sha256='3dd27fe1e3d46880e8579ef979c98014a4bb24ddac1fd4321da7f611bea41ec7'
    v=$(sha256sum "$(readlink -e /etc/pki/tls/certs/ca-bundle.crt)"|awk '{print $1}')
    if [ "${sha256}" = "${v}" ]; then
        return 0
    else
        return 1
    fi
}

update_ca_certificates(){
    cd /tmp || exit 1
    if [ "${os_ver}" = 6 ]; then
        rpm -q ca-certificates-2021.2.50-60.1.el6_10.noarch && return
        check_ca_file_hash && return
        { _download "${ca_url[@]}" && check_ca_rpm_hash && rpm -vhU /tmp/ca-certificates-2021.2.50-60.1.el6_10.noarch.rpm;} || exit 1
    fi
}

test_curl(){
    echo "Test url : https://1.0.0.1/"
    curl -sI https://1.0.0.1/ >/dev/null || { curl -I https://1.0.0.1/; echo "curl is not available"; exit 1;}
}

get_current_sshd_port(){
    sshd_port=$(ss -lnpt4|grep sshd|awk '{print $4}'|awk -F : '{print $2}'|head -1)
    [ -z "${sshd_port}" ] && sshd_port="22"
}

_checkPrivilege
get_current_sshd_port

echo "-------------------------------------------"
echo "openssl            : ${openssl_ver}"
echo "openssh            : ${openssh_ver}"
echo "sshd_port          : ${sshd_port}"
echo "pam                : ${pam}"
echo "use_default_config : ${use_default_config}"
echo "without_openssl    : ${without_openssl}"
echo "Backup             : /etc/pam.d/sshd /etc/pam.d/sshd_bak"
[ "${without_openssl}" = yes ] && echo "[Warning] Your ssh client(SecureCRT >= 8.5.2) must support the following key exchange algorithms:" && printf "\tcurve25519-sha256\n\tcurve25519-sha256@libssh.org\n"
echo "-------------------------------------------"
read -r -n 1 -p "Please confirm the above information. Are you sure you want to continue? [y/n]" input
case $input in
    "y")
        echo
        check_yum
        yum -y install gcc tar perl make pam-devel openssl ca-certificates || exit 1
        test_curl
        update_ca_certificates
        clean_tmp
        build_openssl
        install_openssh
        ;;
    *)
        echo
        exit 1
        ;;
esac
