#!/bin/bash
openssl_ver="openssl-1.1.1o"
nghttp2_ver="nghttp2-1.47.0"
curl_ver="curl-7.83.1"
pycurl_ver="REL_7_43_0_5"

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
    local ver
    ver=$(_sysVer)
    [ "${ver}" -ne 6 ] && return
    [ -f /etc/yum.repos.d/CentOS-Base.repo ] && yum makecache && return
    mv -f /etc/yum.repos.d/CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo.bak >/dev/null 2>&1
    curl --silent -L "https://pan.0db.org:65000/Centos/CentOS-Base.repo" -o /etc/yum.repos.d/CentOS-Base.repo || { echo "CentOS-Base.repo download failed"; exit 3;}
    yum clean all && yum makecache && return
    exit 1
}


build_zlib(){
    cd /tmp || exit 1
    declare -a url=(
        "https://zlib.net/zlib-1.2.11.tar.gz"
        "https://pan.0db.org:65000/dep/zlib-1.2.11.tar.gz"
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
        "https://pan.0db.org:65000/dep/${openssl_ver}.tar.gz"
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
        "https://pan.0db.org:65000/dep/${nghttp2_ver}.tar.gz"
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
        "https://pan.0db.org:65000/dep/${pycurl_ver}.tar.gz"
    )
    { _download "${url[@]}" && tar -axf ${pycurl_ver}.tar.gz && cd pycurl-${pycurl_ver};} || exit 1
    python setup.py docstrings && python setup.py install --curl-config=/usr/bin/curl-config && return
    exit 1
}

install_curl(){
    cd /tmp || exit 1
    declare -a url=(
        "https://curl.se/download/${curl_ver}.tar.gz"
        "https://pan.0db.org:65000/dep/${curl_ver}.tar.gz"
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
    echo "completed"
}

check_ca(){
    readlink -e /etc/pki/tls/certs/ca-bundle.crt || { echo "/etc/pki/tls/certs/ca-bundle.crt not found"; exit 1;}
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

exclude_curl_in_yum(){
    if ! grep "^exclude=" /etc/yum.conf; then
        sed -i "\$aexclude=libcurl curl" /etc/yum.conf
    elif ! grep "^exclude=.*libcurl.*curl" /etc/yum.conf; then
        local options
        local options_libcurl
        local options_curl
        grep "^exclude=.*libcurl" /etc/yum.conf || options_libcurl="libcurl"
        grep "^exclude=.*curl" /etc/yum.conf || options_curl="curl"
        options="$(grep "^exclude=" /etc/yum.conf|awk -F = '{print $2}') ${options_libcurl} ${options_curl}"
        sed -i "\$aexclude=${options}" /etc/yum.conf
    fi
}

check_ca_rpm_hash(){
    local sha256
    local v
    sha256='20a5c2f415a8c873bb759aefa721446452761627789927d997c305472a959c35'
    v=$(sha256sum /tmp/ca-certificates-2021.2.50-60.1.el6_10.noarch.rpm|awk '{print $1}')
    if [ ${sha256} == "${v}" ]; then
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
    if [ ${sha256} == "${v}" ]; then
        return 0
    else
        return 1
    fi
}

update_ca_certificates(){
    cd /tmp || exit 1
    declare -a ca_url=(
        "https://pan.0db.org:65000/dep/ca-certificates-2021.2.50-60.1.el6_10.noarch.rpm"
        "https://github.com/slinar/scripts/raw/master/ca-certificates-2021.2.50-60.1.el6_10.noarch.rpm"
        "https://els6.baruwa.com/els6/ca-certificates-2021.2.50-60.1.el6_10.noarch.rpm"
    )
    if [ "${os_ver}" == 6 ]; then
        rpm -q ca-certificates-2021.2.50-60.1.el6_10.noarch && return
        check_ca_file_hash && return
        { _download "${ca_url[@]}" && check_ca_rpm_hash && rpm -vhU /tmp/ca-certificates-2021.2.50-60.1.el6_10.noarch.rpm;} || exit 1
    fi
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
        yum -y install gcc gcc-c++ perl make python-devel openssl ca-certificates libidn2 libidn2-devel || exit 1
        update_ca_certificates
        check_ca
        clean_tmp
        export CFLAGS="-fPIC"
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
