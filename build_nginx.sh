#!/bin/bash
openssl_ver="openssl-3.0.8"
nginx_ver="nginx-1.24.0"
fancyindex_ver="ngx-fancyindex-0.5.2"
pcre2_ver="pcre2-10.42"
zlib_ver="zlib-1.2.13"

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

download_zlib(){
    cd /tmp || exit 1
    declare -a url=(
        "https://www.zlib.net/${zlib_ver}.tar.gz"
        "https://pan.0db.org:65000/zlib-1.2.13.tar.gz"
    )
    { _download "${url[@]}" && tar -axf ${zlib_ver}.tar.gz && cd ${zlib_ver} && chmod 744 configure;} || exit 1
}

download_openssl(){
    cd /tmp || exit 1
    declare -a url=(
        "https://www.openssl.org/source/${openssl_ver}.tar.gz"
        "https://github.com/openssl/openssl/releases/download/${openssl_ver}/${openssl_ver}.tar.gz"
    )
    { _download "${url[@]}" && tar -axf ${openssl_ver}.tar.gz && cd ${openssl_ver} && chmod 744 config;} || exit 1
}

download_pcre(){
    cd /tmp || exit 1
    declare -a url=(
        "https://pan.0db.org:65000/${pcre2_ver}.tar.gz"
        "https://github.com/PCRE2Project/pcre2/releases/download/${pcre2_ver}/${pcre2_ver}.tar.gz"
    )
    { _download "${url[@]}" && tar -axf ${pcre2_ver}.tar.gz && cd ${pcre2_ver} && chmod 744 configure;} || exit 1
}

build_fancyindex(){
    cd /tmp || exit 1
    declare -a url=(
        "https://pan.0db.org:65000/${fancyindex_ver}.tar.xz"
        "https://github.com/aperezdc/ngx-fancyindex/releases/download/v0.5.2/ngx-fancyindex-0.5.2.tar.xz"
    )
    { _download "${url[@]}" && tar -axf ${fancyindex_ver}.tar.xz && cd ${fancyindex_ver};} || exit 1
    cd /tmp/${nginx_ver} || exit 1
    ./configure --with-compat --add-dynamic-module=/tmp/${fancyindex_ver} || exit 1
    make modules || exit 1
}

build_dav_ext(){
    cd /tmp || exit 1
    declare -a url=(
        "https://pan.0db.org:65000/nginx-dav-ext-module-3.0.0.tar.gz"
        "https://github.com/arut/nginx-dav-ext-module/archive/refs/tags/v3.0.0.tar.gz"
    )
    { _download "${url[@]}" && tar -axf nginx-dav-ext-module-3.0.0.tar.gz && cd nginx-dav-ext-module-3.0.0;} || exit 1
    cd /tmp/${nginx_ver} || exit 1
    ./configure --with-compat --with-http_dav_module --add-dynamic-module=/tmp/nginx-dav-ext-module-3.0.0 || exit 1
    make modules || exit 1
}

# https://nginx.org/en/docs/configure.html
configure_nginx(){
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
    --with-compat \
    --with-file-aio \
    --with-threads \
    --with-openssl=/tmp/${openssl_ver} \
    --with-http_addition_module \
    --with-http_auth_request_module \
    --with-http_dav_module \
    --with-http_flv_module \
    --with-http_gunzip_module \
    --with-http_gzip_static_module \
    --with-http_mp4_module \
    --with-http_realip_module \
    --with-http_secure_link_module \
    --with-http_ssl_module \
    --with-http_v2_module \
    --with-stream \
    --with-stream_realip_module \
    --with-stream_ssl_module \
    --with-stream_ssl_preread_module \
    --with-zlib=/tmp/${zlib_ver} \
    --with-pcre=/tmp/${pcre2_ver} \
    --with-cc-opt='-O3 -pipe -Wall -fPIC' \
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
}

clean_tmp(){
    rm -rf "/tmp/${openssl_ver}"
    rm -rf "/tmp/${zlib_ver}"
    rm -rf "/tmp/${pcre2_ver}"
    rm -rf "/tmp/${fancyindex_ver}"
    rm -rf "/tmp/${nginx_ver}"
    rm -rf "/tmp/nginx-dav-ext-module-3.0.0"
}

list_objs(){
    ls -l /tmp/${nginx_ver}/objs
}

echo
echo "openssl      : ${openssl_ver}"
echo "nginx        : ${nginx_ver}"
echo "fancyindex   : ${fancyindex_ver}"
echo "zlib         : ${zlib_ver} "
echo "pcre2        : ${pcre2_ver}"
echo
echo 'You can execute "nginx.sh index" and install the fancyindex module separately'
read -r -n 1 -p "Are you sure you want to continue? [y/n]" input
case $input in
    "y")
        echo
        yum -y install gcc gcc-c++ perl perl-IPC-Cmd make libxslt-devel ca-certificates || exit 1
        clean_tmp
        download_openssl
        download_zlib
        download_pcre
        build_nginx
        build_fancyindex
        build_dav_ext
        list_objs
        echo 'completed'
        ;;
    *)
        echo
        exit 1
        ;;
esac
