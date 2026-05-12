#!/bin/bash
declare -r libressl_ver="libressl-4.2.1"
declare -r openssl_ver="openssl-3.5.6"
declare -r nginx_ver="nginx-1.30.0"
declare -r pcre2_ver="pcre2-10.47"
declare -r zlib_ver="zlib-1.3.2"

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

cross_env(){
    local TOOLCHAIN_DIR="/tmp/x86_64-linux-musl-cross"
    TARGET="x86_64-linux-musl"
    # MARCH_OPT="-march=westmere"
    # ZLIB_OPT="--disable-crcvx"

    export PATH="${TOOLCHAIN_DIR}/bin:$PATH"
    export CC="${TARGET}-gcc"
    export CXX="${TARGET}-g++"
    export CPP="${TARGET}-cpp"
    export LD="${TARGET}-ld"
    export AR="${TARGET}-ar"
    export AS="${TARGET}-as"
    export RANLIB="${TARGET}-ranlib"
    export STRIP="${TARGET}-strip"
    export CFLAGS="-O3 -fPIC ${MARCH_OPT}"

    declare -a url=(
        "https://musl.cc/${TARGET}-cross.tgz"
    )
    [[ "${TOOLCHAIN_DIR}" == "/tmp/"?* ]] || exit 3
    cd "$(dirname ${TOOLCHAIN_DIR})" || exit 1
    rm -rf ${TOOLCHAIN_DIR}
    { _download "${url[@]}" && tar -axf ${TARGET}-cross.tgz && cd ${TARGET}-cross && chmod 755 bin/*;} || exit 1
}

build_zlib(){
    cd /tmp || exit 1
    declare -a url=(
        "https://www.zlib.net/${zlib_ver}.tar.gz"
    )
    { _download "${url[@]}" && tar -axf ${zlib_ver}.tar.gz && cd ${zlib_ver} && chmod 744 configure;} || exit 1
    ./configure --prefix=/tmp/zlib-static --static "${ZLIB_OPT}" && make && make install || exit 1
}

build_libressl(){
    cd /tmp || exit 1
    declare -a url=(
        "https://cloudflare.cdn.openbsd.org/pub/OpenBSD/LibreSSL/${libressl_ver}.tar.gz"
        "https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/${libressl_ver}.tar.gz"
        "https://cdn.openbsd.org/pub/OpenBSD/LibreSSL/${libressl_ver}.tar.gz"
    )
    { _download "${url[@]}" && tar -axf ${libressl_ver}.tar.gz && cd ${libressl_ver} && chmod 744 configure;} || exit 1
    ./configure --host="${TARGET}" --prefix=/tmp/libressl-static --enable-shared=no --enable-static=yes --disable-tests --with-pic && \
    make && make install || exit 1
}

build_openssl(){
    cd /tmp || exit 1
    declare -ra url=(
        "https://github.com/openssl/openssl/releases/download/${openssl_ver}/${openssl_ver}.tar.gz"
    )
    { _download "${url[@]}" && tar -axf ${openssl_ver}.tar.gz && cd ${openssl_ver} && chmod 744 config;} || exit 1
    ./Configure "$(echo -n ${TARGET}|awk -F'-' '{print $2"-"$1}')" --prefix=/tmp/openssl-static --openssldir=/tmp/openssl-static/ssl no-dso no-async no-tests no-shared no-threads no-weak-ssl-ciphers no-engine no-module no-comp no-zlib no-ssl3 no-tls1 no-tls1_1 no-dtls no-psk no-srp no-idea no-rc2 no-rc4 no-bf no-cast no-md4 no-mdc2 no-camellia no-seed no-deprecated || exit 1
    make && make install_sw && return
    exit 1
}

build_pcre(){
    cd /tmp || exit 1
    declare -a url=(
        "https://github.com/PCRE2Project/pcre2/releases/download/${pcre2_ver}/${pcre2_ver}.tar.gz"
    )
    { _download "${url[@]}" && tar -axf ${pcre2_ver}.tar.gz && cd ${pcre2_ver} && chmod 744 configure;} || exit 1
    ./configure --host="${TARGET}" --prefix=/tmp/pcre2-static --enable-shared=no --enable-static=yes --with-pic && make && make install || exit 1
}

download_ext_modules(){
    cd /tmp || exit 1
    declare -ra fancyindex_url=(
        "https://github.com/aperezdc/ngx-fancyindex/releases/download/v0.6.0/ngx-fancyindex-0.6.0.tar.xz"
    )

    { _download "${fancyindex_url[@]}" && tar -axf ngx-fancyindex-0.6.0.tar.xz && chmod 744 ngx-fancyindex-0.6.0/config;} || exit 1
}

# https://nginx.org/en/docs/configure.html
configure_nginx(){
    unset CC
    unset CPP
    unset CFLAGS
    ./configure \
    --prefix=/etc/nginx \
    --sbin-path=/usr/sbin/nginx \
    --modules-path=/usr/lib64/nginx/modules \
    --conf-path=/etc/nginx/nginx.conf \
    --error-log-path=/var/log/nginx/error.log \
    --http-log-path=/var/log/nginx/access.log \
    --pid-path=/var/run/nginx.pid \
    --lock-path=/var/run/nginx.lock \
    --http-client-body-temp-path=/var/cache/nginx/client_temp \
    --http-proxy-temp-path=/var/cache/nginx/proxy_temp \
    --http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp \
    --http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp \
    --http-scgi-temp-path=/var/cache/nginx/scgi_temp \
    --user=nginx \
    --group=nginx \
    --with-threads \
    --with-http_addition_module \
    --with-http_auth_request_module \
    --with-http_flv_module \
    --with-http_gunzip_module \
    --with-http_gzip_static_module \
    --with-http_mp4_module \
    --with-http_realip_module \
    --with-http_secure_link_module \
    --with-http_ssl_module \
    --with-http_v2_module \
    --with-http_v3_module \
    --with-stream \
    --with-stream_realip_module \
    --with-stream_ssl_module \
    --with-stream_ssl_preread_module \
    --add-module=/tmp/ngx-fancyindex-0.6.0 \
    --with-cc="${TARGET}-gcc -fPIE -static-pie" \
    --with-cpp="${TARGET}-cpp" \
    --with-cc-opt="-I/tmp/openssl-static/include -I/tmp/zlib-static/include -I/tmp/pcre2-static/include -O3 -pipe ${MARCH_OPT}" \
    --with-ld-opt="-L/tmp/openssl-static/lib64 -L/tmp/zlib-static/lib -L/tmp/pcre2-static/lib" \
    || { echo "configure ${nginx_ver} failed!";exit 1;}
}

build_nginx(){
    cd /tmp || exit 1
    declare -a url=(
        "https://nginx.org/download/${nginx_ver}.tar.gz"
    )
    { _download "${url[@]}" && tar -axf ${nginx_ver}.tar.gz && cd ${nginx_ver} && chmod 744 configure;} || exit 1
    [ -f /var/cache/nginx ] && rm -f /var/cache/nginx
    mkdir -p /var/cache/nginx
    useradd -d /var/cache/nginx -s /sbin/nologin -c 'nginx user' nginx
    configure_nginx
    make || exit $?
    mkdir -p /var/cache/nginx
    ${STRIP} objs/nginx
}

clean_tmp(){
    rm -rf /tmp/${zlib_ver}
    rm -rf /tmp/zlib-static
    rm -rf /tmp/${pcre2_ver}
    rm -rf /tmp/pcre2-static
    rm -rf /tmp/${openssl_ver}
    rm -rf /tmp/openssl-static
    rm -rf /tmp/${nginx_ver}
    rm -rf /tmp/ngx-fancyindex-0.6.0
}

echo
echo "openssl      : ${openssl_ver}"
echo "nginx        : ${nginx_ver}"
echo "zlib         : ${zlib_ver} "
echo "pcre2        : ${pcre2_ver}"
echo
read -r -n 1 -p "Do you want to continue? [y/n]" input
case $input in
    "y")
        echo
        yum -y install perl perl-IPC-Cmd make ca-certificates || exit 1
        clean_tmp
        cross_env
        download_ext_modules
        build_zlib
        build_pcre
        build_openssl
        build_nginx
        echo 'completed'
        ;;
    *)
        echo
        exit 1
        ;;
esac
