#!/bin/bash
set -o pipefail

declare -r openssh_ver="openssh-9.9p1"
declare -r openssl_ver="openssl-3.0.15"

# Use default sshd_config. If you want to use your sshd_config, please set this to "no" [yes/no]
declare -r use_default_config="yes"

# Enables PAM support [yes/no]
declare -r pam="no"

# Do not use openssl? [yes/no]
declare -r without_openssl="no"

# Download url
declare -ra openssl_url=(
    "https://github.com/openssl/openssl/releases/download/${openssl_ver}/${openssl_ver}.tar.gz"
)

declare -ra openssh_url=(
    "https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/${openssh_ver}.tar.gz"
    "https://cloudflare.cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/${openssh_ver}.tar.gz"
    "https://mirror.edgecast.com/pub/OpenBSD/OpenSSH/portable/${openssh_ver}.tar.gz"
)

_check_privilege(){
    [ "$(id -u)" -eq 0 ] && return
    echo "Require root privileges"
    exit 1
}

_get_os_version(){
    local v
    local vv
    v=$(uname -r|awk -F "el" '{print $2}')
    vv=${v:0:1}
    if [[ ${vv} = "9" || ${vv} = "8" || ${vv} = "7" || ${vv} = "6" ]]; then
        echo -n "${vv}"
        return
    fi
    exit 2
}

# Generic download function, the parameter is an array of URLs, download to the current directory
_download(){
    local url
    local fileName
    local tarFileName
    local tarOptions
    declare -r urlReg='^(http|https|ftp)://[a-zA-Z0-9\.-]{1,62}\.[a-zA-Z]{1,62}(:[0-9]{1,5})?/.*'
    declare -r fileNameReg='(\.tar\.gz|\.tgz|\.tar\.bz2|\.tar\.xz)$'
    [ -x /usr/bin/xz ] || yum -y install xz
    [ -x /usr/bin/tar ] || [ -x /bin/tar ] || yum -y install tar
    for url in "$@"; do
        if [[ ${url} =~ ${urlReg} ]]; then
            fileName=$(echo "${url}"|awk -F / '{print $NF}')
            if [[ "${fileName}" =~ ${fileNameReg} ]]; then
                tarOptions='-axf'
                tarFileName="${fileName}"
            else
                tarOptions='--version'
                tarFileName=''
            fi
            if [ -f "${fileName}" ]; then
                echo "${fileName} already exists, test ${fileName}"
                tar ${tarOptions} "${tarFileName}" -O > /dev/null && return 0
                echo "Test ${fileName} failed, re-download ${fileName}"
                rm -f "${fileName}"
            fi
            echo "Downloading ${fileName} from ${url}"
            curl --continue-at - --speed-limit 1024 --speed-time 5 --retry 3 --fail --progress-bar --location "${url}" -o "${fileName}" && tar ${tarOptions} "${tarFileName}" -O > /dev/null && return 0
            echo "Failed to download ${fileName} or test ${fileName}, try the next URL or return"
            rm -f "${fileName}"
        fi
    done
    return 1
}

write_CentOS_Base(){
    cat > /etc/yum.repos.d/CentOS-Base.repo<<"EOF"
[base]
name=CentOS-$releasever - Base
baseurl=http://mirrors.aliyun.com/centos-vault/6.10/os/$basearch/
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-6

#released updates 
[updates]
name=CentOS-$releasever - Updates
baseurl=http://mirrors.aliyun.com/centos-vault/6.10/updates/$basearch/
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-6

#additional packages that may be useful
[extras]
name=CentOS-$releasever - Extras
baseurl=http://mirrors.aliyun.com/centos-vault/6.10/extras/$basearch/
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-6

#additional packages that extend functionality of existing packages
[centosplus]
name=CentOS-$releasever - Plus
baseurl=http://mirrors.aliyun.com/centos-vault/6.10/centosplus/$basearch/
gpgcheck=1
enabled=0
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-6

#contrib - packages by Centos Users
[contrib]
name=CentOS-$releasever - Contrib
baseurl=http://mirrors.aliyun.com/centos-vault/6.10/contrib/$basearch/
gpgcheck=1
enabled=0
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-6
EOF
}

check_yum_repositories(){
    if [ "${os_ver}" = 6 ]; then
        if [ -f /etc/yum.repos.d/CentOS-Base.repo ]; then
            yum makecache && yum -y update nss && return
        fi
        mv -f /etc/yum.repos.d/CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo.bak >/dev/null 2>&1
        write_CentOS_Base
        yum clean all && yum makecache && yum -y update nss || exit 1
    fi
}

build_openssl(){
    [ "${without_openssl}" = yes ] && return
    cd /tmp || exit 1
    { _download "${openssl_url[@]}" && tar -axf ${openssl_ver}.tar.gz && cd ${openssl_ver} && chmod 744 config;} || exit 1
    ./config --prefix=/tmp/openssl-static --openssldir=/tmp/openssl-static/ssl -fPIC no-shared no-threads no-weak-ssl-ciphers \
    || { echo "Failed to config openssl";exit 1;}
    make && make install_sw && return
    exit 1
}

modify_iptables(){
    echo "Find iptables rules :"
    iptables -nvL|grep -E "ACCEPT.*(tcp|6).*dpt:${sshd_port}" || \
    iptables -nvL|grep -E "ACCEPT.*(tcp|6).*dports.*[,[:space:]]${sshd_port}," || \
    iptables -nvL|grep -E "ACCEPT.*(tcp|6).*dports.*[,[:space:]]${sshd_port}[[:space:]]*$" && return
    echo "No rules found for accepting port ${sshd_port}"
    iptables -P INPUT DROP
    iptables -P OUTPUT ACCEPT
    iptables -I INPUT -p tcp -m tcp --dport "${sshd_port}" -j ACCEPT
    service iptables save
}

modify_firewalld(){
    echo -n "Check the tcp/22 port in firewalld: "
    if [ "${sshd_port}" = 22 ]; then
        firewall-cmd --query-service=ssh && return
    fi
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
    elif systemctl status iptables.service --no-pager --full; then
        echo "modify_iptables(el8)"
        modify_iptables
    fi
}

write_systemd_service_unit_file(){
    cat > /etc/systemd/system/sshd.service<<"EOF"
[Unit]
Description=OpenSSH server daemon
Documentation=man:sshd(8) man:sshd_config(5)
After=network.target

[Service]
Type=notify
EnvironmentFile=-/etc/crypto-policies/back-ends/opensshserver.config
EnvironmentFile=-/etc/sysconfig/sshd
ExecStartPre=/usr/bin/ssh-keygen -A
ExecStartPre=/usr/sbin/sshd -t
ExecStart=/usr/sbin/sshd -D
ExecReload=/bin/kill -HUP $MAINPID
KillMode=process
Restart=on-failure
RestartSec=42s

[Install]
WantedBy=multi-user.target
EOF

    cat > /etc/sysconfig/sshd<<EOF
# Do not change this option unless you have hardware random
# generator and you REALLY know what you are doing
SSH_USE_STRONG_RNG=0

# System-wide crypto policy:
# To opt-out, uncomment the following line
# CRYPTO_POLICY=
EOF

    chown root:root /etc/systemd/system/sshd.service
    chown root:root /etc/sysconfig/sshd
    chmod 644 /etc/systemd/system/sshd.service
    chmod 640 /etc/sysconfig/sshd
}

privsep(){
    local gid
    local gname
    mkdir -p /var/empty/sshd
    chown root:root /var/empty/sshd
    chmod 711 /var/empty/sshd
    gid=$(grep 'sshd:x:' /etc/passwd|awk -F : '{print $4}')
    if [ -n "${gid}" ];then
        gname=$(grep "${gid}" /etc/group|awk -F : '{print $1}')
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
    elif [ "${os_ver}" = 9 ];then
        modify_sshd_pam_8
    fi
    chown root:root /etc/pam.d/sshd
    chmod 644 /etc/pam.d/sshd
}

modify_sshdconfig(){
    sed -i 's/^[[:space:]#]*Port[[:space:]]\+[[:digit:]]\+[[:space:]]*$/Port '"${sshd_port}"'/' /etc/ssh/sshd_config
    sed -i 's/^[[:space:]]*#\+[[:space:]]*PermitRootLogin[[:space:]]\+.*/PermitRootLogin yes/' /etc/ssh/sshd_config
    sed -i 's/^[[:space:]]*UseDNS[[:space:]]\+yes[[:space:]]*$/#UseDNS no/' /etc/ssh/sshd_config
    sed -i '/^[[:space:]]*GSSAPI.*/d' /etc/ssh/sshd_config
    if [ "${pam}" = yes ]; then
        sed -i 's/^[[:space:]#]*UsePAM[[:space:]]\+no[[:space:]]*$/UsePAM yes/' /etc/ssh/sshd_config
    else
        sed -i 's/^[[:space:]#]*UsePAM[[:space:]]\+yes[[:space:]]*$/#UsePAM no/' /etc/ssh/sshd_config
    fi
    sed -i 's/^#\+[[:space:]]*ClientAliveInterval[[:space:]]\+.*/ClientAliveInterval 30/' /etc/ssh/sshd_config
    sed -i 's/^[[:space:]]*TCPKeepAlive[[:space:]]\+no[[:space:]]*$/#TCPKeepAlive yes/' /etc/ssh/sshd_config
}

modify_selinux(){
    if [ "$(getenforce)" = "Enforcing" ]; then
        sed -i 's/SELINUX=enforcing/SELINUX=disabled/' /etc/selinux/config
        setenforce 0
        echo "The current state of selinux has been modified to $(getenforce)"
    fi
}

generate_host_key(){
    /usr/bin/ssh-keygen -A
}

modify_ssh_file_permission(){
    if [ -d /etc/ssh ]; then
        chown root:root -R /etc/ssh
        chmod 755 /etc/ssh
        chmod 600 /etc/ssh/ssh_host_*_key
        chmod 600 /etc/ssh/sshd_config
        chmod 644 /etc/ssh/ssh_host_*_key.pub
        chmod 644 /etc/ssh/ssh_config
        chmod 644 /etc/ssh/moduli
    else
        echo "/etc/ssh directory not found"
        exit 1
    fi
    if [ -d /root/.ssh ]; then
        chown root:root -R /root/.ssh
        chmod 700 /root/.ssh
        [ -f /root/.ssh/authorized_keys ] && chmod 644 /root/.ssh/authorized_keys
        [ -f /root/.ssh/known_hosts ] && chmod 644 /root/.ssh/known_hosts
    fi
}

modify_el6_sshd_init(){
    [ -f /etc/rc.d/init.d/sshd ] && sed -i 's/ssh_host_dsa_key/ssh_host_ed25519_key/' /etc/rc.d/init.d/sshd
}

sshd_init(){
    case "$1" in
        "install")
            if [ "${os_ver}" = 6 ]; then
                cp -f /tmp/${openssh_ver}/contrib/redhat/sshd.init /etc/rc.d/init.d/sshd
                modify_el6_sshd_init
                chkconfig --add sshd
                chkconfig sshd on
                chown root:root /etc/rc.d/init.d/sshd
                chmod 755 /etc/rc.d/init.d/sshd
            else
                write_systemd_service_unit_file
                systemctl daemon-reload
                systemctl enable sshd.service
            fi
            ;;
        "uninstall")
            if [ "${os_ver}" = 6 ]; then
                chkconfig --del sshd &> /dev/null
                rm -f /etc/rc.d/init.d/sshd
            else
                if systemctl list-unit-files | grep sshd.service > /dev/null; then
                    systemctl stop sshd.service && systemctl disable sshd.service
                fi
                rm -f /usr/lib/systemd/system/sshd-keygen@.service
                rm -f /usr/lib/systemd/system/sshd-keygen.target
                rm -f /usr/lib/systemd/system/sshd.service
                rm -f /usr/lib/systemd/system/sshd@.service
                rm -f /usr/lib/systemd/system/sshd.socket
                rm -f /etc/sysconfig/sshd
                rm -f /etc/systemd/system/sshd.service
            fi
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
    cp -f /etc/pam.d/sshd /etc/pam.d/sshd_bak &> /dev/null
    mv -f /etc/ssh/ssh_config /etc/ssh/ssh_config_bak &> /dev/null
    mv -f /etc/ssh/sshd_config /etc/ssh/sshd_config_bak &> /dev/null
    rpm -e openssh-server
    sshd_init uninstall
    rm -f /etc/ssh/ssh_host_*
    rm -f /etc/ssh/moduli
    rm -rf /var/empty/sshd
}

download_openssh(){
    cd /tmp || exit 1
    { _download "${openssh_url[@]}" && tar -axf ${openssh_ver}.tar.gz && cd ${openssh_ver} && chmod 744 configure;} || exit 1
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
        [ -f /etc/ssh/sshd_config_bak ] && mv -f /etc/ssh/sshd_config_bak /etc/ssh/sshd_config
        [ -f /etc/ssh/ssh_config_bak ] && mv -f /etc/ssh/ssh_config_bak /etc/ssh/ssh_config
    else
        echo "Use the new default sshd_config"
        modify_sshdconfig
    fi
}

# Normally you should uninstall the old version of openssh before installing the new version, but git requires openssh-clients.
# So you cannot remove openssh and openssh-clients, otherwise git will become no longer available.
# You can exclude these two packages from yum or dnf to avoid overwriting openssh and openssh-clients when upgrading your system.
exclude_openssh(){
    local yum_conf_file
    yum_conf_file=/etc/yum.conf
    if [ "${os_ver}" = 8 ] || [ "${os_ver}" = 9 ]; then
        yum_conf_file=/etc/dnf/dnf.conf
    fi
    echo "Exclude openssh, openssh-clients, openssh-server from ${yum_conf_file}"
    if grep -q '^exclude=.*' ${yum_conf_file}; then
        local result
        result=$(grep "^exclude=" ${yum_conf_file}|awk -F = '{print $2}'|xargs echo -n)
        result="${result} openssh openssh-clients openssh-server"
        result=$(echo -n "${result}"|tr ' ' '\n'|sort -u|tr '\n' ' '|xargs echo -n)
        sed -i 's/^exclude=.*/exclude='"${result}"'/' ${yum_conf_file}
    else
        # shellcheck disable=SC2016
        sed -i '$aexclude=openssh openssh-clients openssh-server' ${yum_conf_file}
    fi
}

show_host_key(){
    if [ -x /usr/bin/ssh-keygen ]; then
        ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
        ssh-keygen -lf /etc/ssh/ssh_host_ecdsa_key.pub
        ssh-keygen -lf /etc/ssh/ssh_host_rsa_key.pub
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
    sshd_init start && ssh -V && sshd -V && show_host_key
}

pre_clean_tmp(){
    rm -rf /tmp/${openssl_ver}
    rm -rf /tmp/${openssh_ver}
    rm -rf /tmp/openssl-static
}

test_curl(){
    [ -x "$(which --skip-alias curl)" ] || exit 1
}

# Get the current sshd port, using the first value.If the current sshd port is not available then the default port is used
get_current_sshd_port(){
    sshd_port=$(ss -lnpt|grep sshd|awk '{print $(NF-2)}'|awk -F : '{print $NF}'|head -1)
    [[ ${sshd_port} =~ ^[0-9]+$ ]] || sshd_port="22"
}

initializing_build_environment(){
    yum -y install gcc tar perl perl-IPC-Cmd make pam-devel ca-certificates || exit 1
}

init_os_ver(){
    _get_os_version &> /dev/null
    os_ver=$(_get_os_version)
    readonly os_ver
}

_check_privilege
get_current_sshd_port
init_os_ver

echo "-------------------------------------------"
echo "openssl            : ${openssl_ver}"
echo "openssh            : ${openssh_ver}"
echo "sshd_port          : ${sshd_port}"
echo "pam                : ${pam}"
echo "use_default_config : ${use_default_config}"
echo "without_openssl    : ${without_openssl}"
echo "os_ver             : ${os_ver}"
echo "Backup             : /etc/pam.d/sshd /etc/pam.d/sshd_bak"
echo "-------------------------------------------"

[ "${without_openssl}" = yes ] && \
echo "You chose to build openssh without openssl, only a subset of ciphers and algorithms are supported." && \
cat <<EOF
ssh2-enum-algos: 
  kex_algorithms: (3)
      sntrup761x25519-sha512@openssh.com
      curve25519-sha256
      curve25519-sha256@libssh.org
  server_host_key_algorithms: (1)
      ssh-ed25519
  encryption_algorithms: (4)
      chacha20-poly1305@openssh.com
      aes128-ctr
      aes192-ctr
      aes256-ctr
  mac_algorithms: (10)
      umac-64-etm@openssh.com
      umac-128-etm@openssh.com
      hmac-sha2-256-etm@openssh.com
      hmac-sha2-512-etm@openssh.com
      hmac-sha1-etm@openssh.com
      umac-64@openssh.com
      umac-128@openssh.com
      hmac-sha2-256
      hmac-sha2-512
      hmac-sha1
-------------------------------------------
EOF
# echo 'Please set PermitRootLogin explicitly (without #), otherwise it will be set to yes'
echo
read -r -n 1 -p "Please confirm the above information. do you want to continue? [y/n]" input
case $input in
    "y")
        echo
        check_yum_repositories
        initializing_build_environment
        test_curl
        pre_clean_tmp
        build_openssl
        install_openssh
        exclude_openssh
        echo "completed"
        ;;
    *)
        echo
        exit 1
        ;;
esac
