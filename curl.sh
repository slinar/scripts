#!/bin/bash
set -o pipefail

declare -r zlib_ver="zlib-1.3.1"
openssl_ver="openssl-3.0.18"
declare -r nghttp2_ver="nghttp2-1.68.0"
declare -r curl_ver="curl-8.17.0"
declare -r pycurl_ver="REL_7_43_0_5"
declare -r libunistring_ver="libunistring-1.4.1"
declare -r libidn2_ver="libidn2-2.3.8"
declare -r brotli_ver="v1.1.0"
declare -r cmake_ver="cmake-3.27.9-linux-x86_64"

_checkPrivilege(){
    test "$(id -u)" -eq 0 && return
    echo "Require root privileges"
    exit 1
}

_os_version(){
    [[ $(uname -r) =~ el[1-9][0-9_.]+ ]] || { echo "Unrecognized kernel: $(uname -r)"; exit 1;}
    printf -v os_ver '%d' "$(uname -r|awk -F el '{print $2}'|awk -F '[._]' '{print $1}')" || exit 1
    readonly os_ver
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
    local zlib_ver_num
    zlib_ver_num="$(awk -F '-' '{print $2}' <<< ${zlib_ver})"
    declare -ra url=(
        "https://zlib.net/${zlib_ver}.tar.gz"
        "https://github.com/madler/zlib/releases/download/v${zlib_ver_num}/${zlib_ver}.tar.gz"
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

build_libunistring(){
    cd /tmp || exit 1
    declare -ra url=(
        "https://mirrors.kernel.org/gnu/libunistring/${libunistring_ver}.tar.gz"
    )
    { _download "${url[@]}" && tar -axf ${libunistring_ver}.tar.gz && cd ${libunistring_ver} && chmod 744 configure;} || exit 1
    ./configure --prefix=/tmp/libunistring-static --disable-rpath --disable-shared --disable-dependency-tracking --enable-year2038
    make && make install && return
    exit 1
}

build_libidn2(){
    cd /tmp || exit 1
    declare -ra url=(
        "https://mirrors.kernel.org/gnu/libidn/${libidn2_ver}.tar.gz"
    )
    { _download "${url[@]}" && tar -axf ${libidn2_ver}.tar.gz && cd ${libidn2_ver} && chmod 744 configure;} || exit 1
    ./configure --with-libunistring-prefix=/tmp/libunistring-static --prefix=/tmp/libidn2-static --disable-shared
    make && make install && return
    exit 1
}

build_brotli(){
    cd /tmp || exit 1
    local ver_num
    brotli_num="$(awk -F v '{print $NF}' <<< ${brotli_ver})"
    declare -ra url=(
        "https://github.com/google/brotli/archive/refs/tags/${brotli_ver}.tar.gz"
    )
    { _download "${url[@]}" && tar -axf ${brotli_ver}.tar.gz && cd brotli-"${brotli_num}" && [ -f CMakeLists.txt ];} || exit 1
    mkdir -p out && cd out || exit 1
    cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/tmp/brotli-static -DBUILD_SHARED_LIBS=OFF .. || exit 1
    cmake --build . --config Release --target install || exit 1
    cd /tmp && rm -rf brotli-"${brotli_num}"
}

download_cmake(){
    cd /tmp || exit 1
    local major_ver
    local major_minor_ver
    major_ver="$(awk -F '[.-]' '{print $2 "." $3}' <<< ${cmake_ver})"
    major_minor_ver="$(awk -F '-' '{print $2}' <<< ${cmake_ver})"
    declare -ra url=(
        "https://cmake.org/files/v${major_ver}/${cmake_ver}.tar.gz"
        "https://github.com/Kitware/CMake/releases/download/v${major_minor_ver}/${cmake_ver}.tar.gz"
    )
    { _download "${url[@]}" && tar -axf ${cmake_ver}.tar.gz && chmod 755 /tmp/${cmake_ver}/bin/*;} || exit 1
    export PATH=/tmp/${cmake_ver}/bin:${PATH}
    [ -x /tmp/${cmake_ver}/bin/cmake ] || exit 3
    cmake --version || exit 4
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
    export PKG_CONFIG_PATH=/tmp/zlib-static/lib/pkgconfig:/tmp/brotli-static/lib64/pkgconfig:/tmp/nghttp2-static/lib/pkgconfig:/tmp/libidn2-static/lib/pkgconfig
    export PKG_CONFIG="pkg-config --static"
    ./configure --prefix=/usr --libdir=/usr/lib64 --enable-optimize --with-ca-bundle=/etc/pki/tls/certs/ca-bundle.crt --with-ssl=/tmp/openssl-static --with-nghttp2 --with-brotli --with-libidn2 --without-libpsl || exit 1
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
    rm -rf /tmp/${libidn2_ver}
    rm -rf /tmp/libidn2-static
    rm -rf /tmp/${libunistring_ver}
    rm -rf /tmp/libunistring-static
    rm -rf /tmp/${cmake_ver}
    rm -rf /tmp/brotli-static 
}

exclude_curl_in_yum(){
    local yum_conf_file
    yum_conf_file=/etc/yum.conf
    if [ "${os_ver}" != 6 ] && [ "${os_ver}" != 7 ]; then
        yum_conf_file=/etc/dnf/dnf.conf
    fi
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
    yum -y install gcc gcc-c++ perl perl-IPC-Cmd perl-Time-Piece make ca-certificates pkgconfig || exit 1
    if [ "${os_ver}" = 6 ] || [ "${os_ver}" = 7 ];then
        yum -y install python-devel curl libcurl python-pycurl nss || exit 1
    fi
    export CFLAGS="-fPIC -O3 -Wno-error=unknown-pragmas -Wno-error=sign-compare -Wno-error=cast-align"
}

_os_version
if [ "${os_ver}" = 6 ] || [ "${os_ver}" = 7 ]; then
    openssl_ver="openssl-1.1.1w"
fi
readonly openssl_ver

echo "-------------------------------------------"
echo "openssl      : ${openssl_ver}"
echo "nghttp2      : ${nghttp2_ver}"
echo "curl         : ${curl_ver}"
echo "pycurl       : ${pycurl_ver}"
echo "zlib         : ${zlib_ver}"
echo "libunistring : ${libunistring_ver}"
echo "libidn2      : ${libidn2_ver}"
echo "brotli       : ${brotli_ver}"
echo "cmake        : ${cmake_ver}"
echo "os_ver       : ${os_ver}"
echo "TIME         : $(date +"%Y-%m-%d %H:%M:%S %Z")"
echo "-------------------------------------------"
read -r -n 1 -p "Do you want to continue? [y/n/c]" input
case $input in
    "y")
        echo
        _checkPrivilege
        check_yum_repositories
        initializing_build_environment
        update_ca_file
        check_ca_file
        clean_tmp
        download_cmake
        build_brotli
        build_libunistring
        build_libidn2
        build_zlib
        build_openssl
        build_nghttp2
        install_curl
        install_pycurl
        exclude_curl_in_yum
        show_curl_ver
        ;;
    "c")
        echo
        clean_tmp
        ;;
    *)
        echo
        exit 1
        ;;
esac
