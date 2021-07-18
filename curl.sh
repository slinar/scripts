#!/bin/bash
openssl_ver="openssl-1.1.1k"
nghttp2_ver="nghttp2-1.44.0"
curl_ver="curl-7.77.0"
pycurl_ver="REL_7_43_0_5"

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
            echo "Downloading ${fileName} from ${url}"
            #wget --continue --timeout=10 --tries=3 --retry-connrefused -O "${fileName}" "${url}" && tar ${tarOptions} "${tarFileName}" -O >/dev/null && return 0
            curl --continue-at - --speed-limit 1024 --speed-time 5 --retry 3 --progress-bar --location "${url}" -o "${fileName}" && tar ${tarOptions} "${tarFileName}" -O >/dev/null && return 0
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
    curl --silent -L "http://121.46.231.197:5900/directlink/2/el6/CentOS-Base.repo" -o /etc/yum.repos.d/CentOS-Base.repo || { echo "CentOS-Base.repo download failed"; exit 3;}
    yum clean all && yum makecache && return
    exit 1
}


build_zlib(){
    cd /tmp || exit 1
    declare -a url=(
        "https://zlib.net/zlib-1.2.11.tar.gz"
        "https://pan.0db.org:59000/dep/zlib-1.2.11.tar.gz"
    )
    { _download "${url[@]}" && tar -axf zlib-1.2.11.tar.gz && cd zlib-1.2.11 && chmod 744 configure;} || exit 1
    ./configure --prefix=/tmp/zlib-static --static || exit 1
    make && make install && return
    exit 1
}

build_openssl(){
    cd /tmp || exit 1
    declare -a url=(
        "https://www.openssl.org/source/${openssl_ver}.tar.gz"
        "https://pan.0db.org:59000/dep/${openssl_ver}.tar.gz"
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
    declare -a url=(
        "https://github.com/nghttp2/nghttp2/releases/download/v${ver_num}/${nghttp2_ver}.tar.gz"
        "https://pan.0db.org:59000/dep/${nghttp2_ver}.tar.gz"
    )
    { _download "${url[@]}" && tar -axf ${nghttp2_ver}.tar.gz && cd ${nghttp2_ver} && chmod 744 configure;} || exit 1
    export OPENSSL_LIBS=/tmp/openssl-static
    ./configure --prefix=/tmp/nghttp2-static --enable-lib-only --enable-shared=no
    make && make install && return
    exit 1
}

install_pycurl(){
    cd /tmp || exit 1
    declare -a url=(
        "https://github.com/pycurl/pycurl/archive/refs/tags/${pycurl_ver}.tar.gz"
        "https://pan.0db.org:59000/dep/${pycurl_ver}.tar.gz"
    )
    { _download "${url[@]}" && tar -axf ${pycurl_ver}.tar.gz && cd pycurl-${pycurl_ver};} || exit 1
    python setup.py docstrings && python setup.py install --curl-config=/usr/bin/curl-config && return
    exit 1
}

install_curl(){
    cd /tmp || exit 1
    declare -a url=(
        "https://curl.se/download/${curl_ver}.tar.gz"
        "https://pan.0db.org:59000/dep/${curl_ver}.tar.gz"
    )
    { _download "${url[@]}" && tar -axf ${curl_ver}.tar.gz && cd ${curl_ver} && chmod 744 configure;} || exit 1
    ./configure \
    --prefix=/usr \
    --libdir=/usr/lib64 \
    --enable-optimize \
    --with-openssl=/tmp/openssl-static \
    --with-zlib=/tmp/zlib-static \
    --with-nghttp2=/tmp/nghttp2-static \
    --with-libidn2 \
    --with-ca-bundle=/etc/pki/tls/certs/ca-bundle.crt \
    || exit 1
    make && make install && return
    exit 1
}

show_curl_ver(){
    curl --version || echo 'curl is not installed correctly!'
}

check_ca(){
    readlink -fe /etc/pki/tls/certs/ca-bundle.crt || { echo "/etc/pki/tls/certs/ca-bundle.crt not found"; exit 1;}
}

clean_tmp(){
    rm -rf /tmp/zlib-1.2.11
    rm -rf /tmp/zlib-static
    rm -rf /tmp/${openssl_ver}
    rm -rf /tmp/openssl-static
    rm -rf /tmp/${nghttp2_ver}
    rm -rf /tmp/nghttp2-static
    rm -rf /tmp/pycurl-${pycurl_ver}
    rm -rf /tmp/${curl_ver}
}

echo "-------------------------------------------"
echo "openssl : ${openssl_ver}"
echo "nghttp2 : ${nghttp2_ver}"
echo "curl    : ${curl_ver}"
echo "pycurl  : ${pycurl_ver}"
echo "-------------------------------------------"
read -r -n 1 -p "Are you sure you want to continue? [y/n]" input
case $input in
    "y")
        echo
        _sysVer
        _checkPrivilege
        check_yum
        yum -y install gcc gcc-c++ wget perl make python-devel ca-certificates libidn2 libidn2-devel || exit 1
        check_ca
        clean_tmp
        export CFLAGS="-fPIC"
        build_zlib
        build_openssl
        build_nghttp2
        install_curl
        install_pycurl
        show_curl_ver
        ;;
    *)
        echo
        exit 1
        ;;
esac
