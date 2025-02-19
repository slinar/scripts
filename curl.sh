#!/bin/bash
set -o pipefail

declare -r zlib_ver="zlib-1.3.1"
openssl_ver="openssl-3.4.1"
declare -r nghttp2_ver="nghttp2-1.64.0"
declare -r curl_ver="curl-8.12.0"
declare -r pycurl_ver="REL_7_43_0_5"

_checkPrivilege(){
    test "$(id -u)" -eq 0 && return
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
                tar ${tarOptions} "${tarFileName}" -O >/dev/null && return 0
                echo "Test ${fileName} failed, re-download ${fileName}"
                rm -f "${fileName}"
            fi
            echo "Downloading ${fileName} from ${url}"
            curl --continue-at - --speed-limit 1024 --speed-time 5 --retry 3 --fail --progress-bar --location "${url}" -o "${fileName}" && tar ${tarOptions} "${tarFileName}" -O >/dev/null && return 0
            echo "Failed to download ${fileName} or test ${fileName}, try the next URL or return"
            rm -f "${fileName}"
        fi
    done
    return 1
}

write_CentOS_Base_6(){
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

write_CentOS_Base_7(){
    cat > /etc/yum.repos.d/CentOS-Base.repo<<"EOF"
[base]
name=CentOS-$releasever - Base
baseurl=http://mirrors.aliyun.com/centos-vault/7.9.2009/os/$basearch/
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7

#released updates 
[updates]
name=CentOS-$releasever - Updates
baseurl=http://mirrors.aliyun.com/centos-vault/7.9.2009/updates/$basearch/
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7

#additional packages that may be useful
[extras]
name=CentOS-$releasever - Extras
baseurl=http://mirrors.aliyun.com/centos-vault/7.9.2009/extras/$basearch/
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7

#additional packages that extend functionality of existing packages
[centosplus]
name=CentOS-$releasever - Plus
baseurl=http://mirrors.aliyun.com/centos-vault/7.9.2009/centosplus/$basearch/
gpgcheck=1
enabled=0
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7
EOF
}

check_yum_repositories(){
    if [ "${os_ver}" = 6 ] || [ "${os_ver}" = 7 ]; then
        if [ -f /etc/yum.repos.d/CentOS-Base.repo ]; then
            yum makecache && return
        fi
        mv -f /etc/yum.repos.d/CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo.bak >/dev/null 2>&1
        [ "${os_ver}" = 6 ] && write_CentOS_Base_6
        [ "${os_ver}" = 7 ] && write_CentOS_Base_7
        yum clean all && yum makecache || exit 1
    fi
}

build_zlib(){
    cd /tmp || exit 1
    declare -ra url=(
        "https://zlib.net/${zlib_ver}.tar.gz"
    )
    { _download "${url[@]}" && tar -axf ${zlib_ver}.tar.gz && cd ${zlib_ver} && chmod 744 configure;} || exit 1
    ./configure --prefix=/tmp/zlib-static --static || exit 1
    make && make install && return
    exit 1
}

build_openssl(){
    cd /tmp || exit 1
    if [ "${os_ver}" = 6 ] || [ "${os_ver}" = 7 ]; then
        declare -ra url=(
            "https://github.com/openssl/openssl/releases/download/OpenSSL_1_1_1w/openssl-1.1.1w.tar.gz"
        )
    else
        declare -ra url=(
            "https://github.com/openssl/openssl/releases/download/${openssl_ver}/${openssl_ver}.tar.gz"
        )
    fi
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
    if [ "${os_ver}" = 6 ] || [ "${os_ver}" = 7 ]; then
        cd /tmp || exit 1
        declare -ra url=(
            "https://github.com/pycurl/pycurl/archive/refs/tags/${pycurl_ver}.tar.gz"
        )
        { _download "${url[@]}" && tar -axf ${pycurl_ver}.tar.gz && cd pycurl-${pycurl_ver};} || exit 1
        /usr/bin/python setup.py docstrings && /usr/bin/python setup.py install --openssl-dir=/tmp/openssl-static && return
        exit 1
    fi
}

install_curl(){
    cd /tmp || exit 1
    declare -ra url=(
        "https://curl.se/download/${curl_ver}.tar.gz"
    )
    { _download "${url[@]}" && tar -axf ${curl_ver}.tar.gz && cd ${curl_ver} && chmod 744 configure;} || exit 1
    export PKG_CONFIG_PATH=/tmp/zlib-static/lib/pkgconfig:/tmp/nghttp2-static/lib/pkgconfig
    ./configure --prefix=/usr --libdir=/usr/lib64 --enable-optimize --with-ca-bundle=/etc/pki/tls/certs/ca-bundle.crt --with-ssl=/tmp/openssl-static --without-libpsl || exit 1
    make && make install && return
    exit 1
}

show_curl_ver(){
    curl --version || echo 'curl is not installed correctly!'
    echo "completed"
}

check_ca_file(){
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

update_ca_file(){
    if [ "${os_ver}" = 6 ]; then
        cd /tmp || exit 1
        local ca_path
        local ca_url="https://curl.se/ca/cacert.pem"
        ca_path=$(readlink -e /etc/pki/tls/certs/ca-bundle.crt)
        [ -z "${ca_path}" ] && echo "ca_path is empty" && exit 1
        [ ! -f "${ca_path}" ] && echo "${ca_path} is not a file" && exit 1
        if [ $(($(date +%s) - $(stat --format="%Y" "${ca_path}"))) -gt 63072000 ]; then
            echo "Downloading cacert.pem from ${ca_url}"
            curl --continue-at - --fail --speed-limit 1024 --speed-time 5 --retry 3 -k --progress-bar -o ca_file_tmp "${ca_url}" && mv -f ca_file_tmp "${ca_path}"
        fi
    fi
}

initializing_build_environment(){
    yum -y install gcc gcc-c++ perl perl-IPC-Cmd make ca-certificates pkgconfig || exit 1
    if [ "${os_ver}" = 6 ] || [ "${os_ver}" = 7 ];then
        yum -y install python-devel curl libcurl python-pycurl nss || exit 1
    fi
    yum -y install brotli-devel libidn2-devel
    export CFLAGS="-fPIC -O2"
}

_get_os_version &> /dev/null
os_ver=$(_get_os_version)
if [ "${os_ver}" = 6 ] || [ "${os_ver}" = 7 ]; then
    openssl_ver="openssl-1.1.1w"
fi
readonly os_ver
readonly openssl_ver

echo "-------------------------------------------"
echo "openssl : ${openssl_ver}"
echo "nghttp2 : ${nghttp2_ver}"
echo "curl    : ${curl_ver}"
echo "pycurl  : ${pycurl_ver}"
echo "zlib    : ${zlib_ver}"
echo "os_ver  : ${os_ver}"
echo "TIME    : $(date +"%Y-%m-%d %H:%M:%S %Z")"
echo "-------------------------------------------"
read -r -n 1 -p "Do you want to continue? [y/n]" input
case $input in
    "y")
        echo
        _checkPrivilege
        check_yum_repositories
        initializing_build_environment
        update_ca_file
        check_ca_file
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
