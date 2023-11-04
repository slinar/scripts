#!/bin/bash
zlib_ver="zlib-1.3"
openssl_ver="openssl-3.0.12"
nghttp2_ver="nghttp2-1.58.0"
curl_ver="curl-8.4.0"
pycurl_ver="REL_7_43_0_5"

_checkPrivilege(){
    test "$(id -u)" -eq 0 && return
    echo "Require root privileges"
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
if [ "${os_ver}" != 8 ]; then
    openssl_ver="openssl-1.1.1w"
fi

# Generic download function, the parameter is an array of URLs, download to the current directory
_download(){
    local url
    local fileName
    local tarFileName
    local tarOptions
    declare -r urlReg='^(http|https|ftp)://[a-zA-Z0-9\.-]{1,62}\.[a-zA-Z]{1,62}(:[0-9]{1,5})?/.*'
    declare -r fileNameReg='(\.tar\.gz|\.tgz|\.tar\.bz2|\.tar\.xz)$'
    [ ! -x /usr/bin/xz ] && yum -y install xz
    [ ! -x /usr/bin/tar ] && yum -y install tar
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
                tar ${tarOptions} "${tarFileName}" -O >/dev/null && return 0
                echo "Test ${fileName} failed, re-download ${fileName}"
                rm -f "${fileName}"
            fi
            echo "Downloading ${fileName} from ${url}"
            curl --continue-at - --speed-limit 10240 --speed-time 5 --retry 3 --progress-bar --location "${url}" -o "${fileName}" && tar ${tarOptions} "${tarFileName}" -O >/dev/null && return 0
            echo "Failed to download ${fileName} or test ${fileName}, try the next URL or return"
            rm -f "${fileName}"
        fi
    done
    return 1
}

write_CentOS_Base(){
    cat > /etc/yum.repos.d/CentOS-Base.repo<<"EOF"
# CentOS-Base.repo
#
# The mirror system uses the connecting IP address of the client and the
# update status of each mirror to pick mirrors that are updated to and
# geographically close to the client.  You should use this for CentOS updates
# unless you are manually picking other mirrors.
#
# If the mirrorlist= does not work for you, as a fall back you can try the 
# remarked out baseurl= line instead.
#
#

[base]
name=CentOS-$releasever - Base
#mirrorlist=http://mirrorlist.centos.org/?release=$releasever&arch=$basearch&repo=os&infra=$infra
baseurl=https://vault.centos.org/6.10/os/$basearch/
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-6

#released updates 
[updates]
name=CentOS-$releasever - Updates
#mirrorlist=http://mirrorlist.centos.org/?release=$releasever&arch=$basearch&repo=updates&infra=$infra
baseurl=https://vault.centos.org/6.10/updates/$basearch/
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-6

#additional packages that may be useful
[extras]
name=CentOS-$releasever - Extras
#mirrorlist=http://mirrorlist.centos.org/?release=$releasever&arch=$basearch&repo=extras&infra=$infra
baseurl=https://vault.centos.org/6.10/extras/$basearch/
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-6

#additional packages that extend functionality of existing packages
[centosplus]
name=CentOS-$releasever - Plus
#mirrorlist=http://mirrorlist.centos.org/?release=$releasever&arch=$basearch&repo=centosplus&infra=$infra
baseurl=https://vault.centos.org/6.10/centosplus/$basearch/
gpgcheck=1
enabled=0
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-6

#contrib - packages by Centos Users
[contrib]
name=CentOS-$releasever - Contrib
#mirrorlist=http://mirrorlist.centos.org/?release=$releasever&arch=$basearch&repo=contrib&infra=$infra
baseurl=https://vault.centos.org/6.10/contrib/$basearch/
gpgcheck=1
enabled=0
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-6
EOF
}

check_yum(){
    [ "${os_ver}" != 6 ] && return
    [ -f /etc/yum.repos.d/CentOS-Base.repo ] && yum makecache && return
    mv -f /etc/yum.repos.d/CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo.bak >/dev/null 2>&1
    write_CentOS_Base
    yum clean all && yum makecache && return
    exit 1
}

build_zlib(){
    cd /tmp || exit 1
    declare -ra url=(
        "https://zlib.net/${zlib_ver}.tar.gz"
        "https://pan.0db.org:65000/${zlib_ver}.tar.gz"
    )
    { _download "${url[@]}" && tar -axf ${zlib_ver}.tar.gz && cd ${zlib_ver} && chmod 744 configure;} || exit 1
    ./configure --prefix=/tmp/zlib-static --static || exit 1
    make && make install && return
    exit 1
}

build_openssl(){
    cd /tmp || exit 1
    declare -ra url=(
        "https://www.openssl.org/source/${openssl_ver}.tar.gz"
        "https://github.com/openssl/openssl/releases/download/${openssl_ver}/${openssl_ver}.tar.gz"
    )
    { _download "${url[@]}" && tar -axf ${openssl_ver}.tar.gz && cd ${openssl_ver} && chmod 744 config;} || exit 1
    ./config --prefix=/tmp/openssl-static --openssldir=/tmp/openssl-static/ssl -fPIC no-shared no-threads || exit 1
    make && make install_sw && return
    exit 1
}

build_nghttp2(){
    cd /tmp || exit 1
    local ver_num
    ver_num=${nghttp2_ver:8:6}
    declare -ra url=(
        "https://github.com/nghttp2/nghttp2/releases/download/v${ver_num}/${nghttp2_ver}.tar.gz"
    )
    { _download "${url[@]}" && tar -axf ${nghttp2_ver}.tar.gz && cd ${nghttp2_ver} && chmod 744 configure;} || exit 1
    ./configure --prefix=/tmp/nghttp2-static --enable-lib-only --enable-shared=no
    make && make install && return
    exit 1
}

install_pycurl(){
    [ "${os_ver}" = 8 ] && return
    cd /tmp || exit 1
    declare -ra url=(
        "https://github.com/pycurl/pycurl/archive/refs/tags/${pycurl_ver}.tar.gz"
    )
    { _download "${url[@]}" && tar -axf ${pycurl_ver}.tar.gz && cd pycurl-${pycurl_ver};} || exit 1
    /usr/bin/python setup.py docstrings && /usr/bin/python setup.py install --openssl-dir=/tmp/openssl-static && return
    exit 1
}

install_curl(){
    cd /tmp || exit 1
    local brotli_opt
    brotli_opt="--with-brotli"
    if [ "${os_ver}" = 6 ];then
        brotli_opt="--without-brotli"
    fi
    declare -ra url=(
        "https://curl.se/download/${curl_ver}.tar.gz"
    )
    { _download "${url[@]}" && tar -axf ${curl_ver}.tar.gz && cd ${curl_ver} && chmod 744 configure;} || exit 1
    export PKG_CONFIG_PATH=/tmp/zlib-static/lib/pkgconfig:/tmp/nghttp2-static/lib/pkgconfig
    ./configure --prefix=/usr --libdir=/usr/lib64 --enable-optimize --with-ca-bundle=/etc/pki/tls/certs/ca-bundle.crt --with-ssl=/tmp/openssl-static "${brotli_opt}" --with-libidn2 --without-libpsl || exit 1
    make && make install && return
    exit 1
}

show_curl_ver(){
    curl --version || echo 'curl is not installed correctly!'
    if [ "${ca_certificates_flag}" = 1 ]; then
        echo "ca-certificates may need to be updated"
        rpm -q ca-certificates
    fi
    echo "completed"
}

check_ca(){
    readlink -e /etc/pki/tls/certs/ca-bundle.crt || { echo "/etc/pki/tls/certs/ca-bundle.crt not found"; exit 1;}
}

clean_tmp(){
    rm -rf /tmp/${zlib_ver}
    rm -rf /tmp/zlib-static
    rm -rf /tmp/${openssl_ver}
    rm -rf /tmp/openssl-static
    rm -rf /tmp/${nghttp2_ver}
    rm -rf /tmp/nghttp2-static
    rm -rf /tmp/pycurl-${pycurl_ver}
    rm -rf /tmp/${curl_ver}
}

exclude_curl_in_yum(){
    local yum_conf_file
    yum_conf_file=/etc/yum.conf
    [ "${os_ver}" = 8 ] && yum_conf_file=/etc/dnf/dnf.conf
    echo "Exclude curl and libcurl from ${yum_conf_file}"
    if grep -q '^exclude=.*' ${yum_conf_file}; then
        local result
        result=$(grep "^exclude=" ${yum_conf_file}|awk -F = '{print $2}'|xargs echo -n)
        result="${result} libcurl curl python-pycurl"
        result=$(echo -n "${result}"|tr ' ' '\n'|sort -u|tr '\n' ' '|xargs echo -n)
        sed -i 's/^exclude=.*/exclude='"${result}"'/' ${yum_conf_file}
    else
        # shellcheck disable=SC2016
        sed -i '$aexclude=libcurl curl python-pycurl' ${yum_conf_file}
    fi
}

update_ca_certificates(){
    if [ "${os_ver}" = 6 ]; then
        cd /tmp || exit 1
        declare -ra ca_url=(
            "http://dl.marmotte.net/rpms/redhat/el6/x86_64/ca-certificates-2021.2.50-65.1.ex1.el6_10/ca-certificates-2021.2.50-65.1.ex1.el6_10.noarch.rpm"
        )
        rpm -q ca-certificates-2021.2.50-65.1.ex1.el6_10.noarch && return
        { _download "${ca_url[@]}" && rpm -vhU /tmp/ca-certificates-2021.2.50-65.1.ex1.el6_10.noarch.rpm;} || ca_certificates_flag=1
    fi
}

initializing_build_environment(){
    yum -y install gcc gcc-c++ perl perl-IPC-Cmd make ca-certificates libidn2-devel || exit 1
    if [ "${os_ver}" = 8 ];then
        yum -y install brotli-devel || exit 1
    fi
    if [ "${os_ver}" = 7 ];then
        yum -y install epel-release || exit 1
        yum -y install brotli-devel || exit 1
    fi
    if [ "${os_ver}" != 8 ];then
        yum -y install nss-tools python-devel curl libcurl python-pycurl || exit 1
    fi
    export CFLAGS="-fPIC -O3"
}

echo "-------------------------------------------"
echo "openssl : ${openssl_ver}"
echo "nghttp2 : ${nghttp2_ver}"
echo "curl    : ${curl_ver}"
echo "pycurl  : ${pycurl_ver}"
echo "zlib    : ${zlib_ver}"
echo "-------------------------------------------"
read -r -n 1 -p "Do you want to continue? [y/n]" input
case $input in
    "y")
        echo
        _sysVer
        _checkPrivilege
        check_yum
        initializing_build_environment
        update_ca_certificates
        check_ca
        clean_tmp
        build_zlib
        build_openssl
        build_nghttp2
        install_curl
        install_pycurl
        exclude_curl_in_yum
        show_curl_ver
        ;;
    *)
        echo
        exit 1
        ;;
esac
