#!/bin/bash

openssl_ver="openssl-1.1.1k"
pcre_ver="pcre-8.45"
nginx_ver="nginx-1.20.1"
fancyindex_ver="ngx-fancyindex-0.5.1"

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
            curl --continue-at - --speed-limit 10240 --speed-time 5 --retry 3 --progress-bar --location "${url}" -o "${fileName}" && tar ${tarOptions} "${tarFileName}" -O >/dev/null && return 0
            rm -f "${fileName}"
        fi
    done
    return 1
}

download_zlib(){
    cd /tmp || exit 1
    declare -a url=(
        "https://zlib.net/zlib-1.2.11.tar.gz"
    )
    { _download "${url[@]}" && tar -axf zlib-1.2.11.tar.gz && cd zlib-1.2.11 && chmod 744 configure;} || exit 1
}

download_openssl(){
    cd /tmp || exit 1
    declare -a url=(
        "https://www.openssl.org/source/${openssl_ver}.tar.gz"
    )
    { _download "${url[@]}" && tar -axf ${openssl_ver}.tar.gz && cd ${openssl_ver} && chmod 744 config;} || exit 1
}

download_pcre(){
    cd /tmp || exit 1
    declare -a url=(
        "https://ftp.pcre.org/pub/pcre/${pcre_ver}.tar.gz"
    )
    { _download "${url[@]}" && tar -axf ${pcre_ver}.tar.gz && cd ${pcre_ver} && chmod 744 configure;} || exit 1
}

install_fancyindex(){
    cd /tmp || exit 1
    declare -a url=(
        "https://pan.0db.org:65000/dep/${fancyindex_ver}.tar.xz"
    )
    { _download "${url[@]}" && tar -axf ${fancyindex_ver}.tar.xz && cd ${fancyindex_ver};} || exit 1
    cd /tmp/${nginx_ver} || exit 1
    chmod 744 configure || exit 1
    local src_ver
    local curr_ver
    src_ver=$(strings /usr/sbin/nginx|grep 'nginx version'|awk -F '/' '{print $2}')
    curr_ver=$(grep NGINX_VERSION src/core/nginx.h|grep -vE 'grep|/'|awk '{print $3}'|tr -d '"')
    [ "${src_ver}" != "${curr_ver}" ] && echo "Source nginx_version and current_versions do not match! Failed to install fancyindex!" && exit 1
    ./configure --with-compat --add-dynamic-module=/tmp/${fancyindex_ver} || { echo "ERROR: configure ${fancyindex_ver} with ${nginx_ver}";exit 1;}
    make modules || { echo "ERROR: make ${fancyindex_ver} with ${nginx_ver}";exit 1;}
    [ ! -f objs/ngx_http_fancyindex_module.so ] && echo "ERROR: build fancyindex success, but /tmp/${nginx_ver}/objs/ngx_http_fancyindex_module.so not found!" && exit 1
    mkdir -p /usr/lib64/nginx/modules || exit 1
    cp -f objs/ngx_http_fancyindex_module.so /usr/lib64/nginx/modules/ngx_http_fancyindex_module.so || exit 1
    local count
    count=$(grep load_module /etc/nginx/nginx.conf|grep '/usr/lib64/nginx/modules/ngx_http_fancyindex_module.so'|grep -cv '#')
    [ "${count}" -eq 0 ] && sed -i '1iload_module /usr/lib64/nginx/modules/ngx_http_fancyindex_module.so;' /etc/nginx/nginx.conf
    nginx -t && service nginx restart && echo 'completed'
}

uninstall_old_nginx(){
    [ -d /etc/nginx ] && mv /etc/nginx /etc/nginx_bak
    yum -y remove nginx
    [ -d /etc/nginx_bak ] && mv /etc/nginx_bak /etc/nginx
    local pid
    pid=$(pgrep -ofP "$(cat /proc/sys/kernel/core_uses_pid)" /usr/sbin/nginx)
    pkill -s "${pid}"
    rm -f /var/lock/subsys/nginx
    rm -f /var/run/nginx.pid
    chkconfig --del nginx >/dev/null 2>&1
    rm -f /usr/sbin/nginx
    rm -f /etc/rc.d/init.d/nginx
    rm -rf /var/cache/nginx
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
    --with-http_addition_module \
    --with-http_auth_request_module \
    --with-http_dav_module \
    --with-http_flv_module \
    --with-http_gunzip_module \
    --with-http_gzip_static_module \
    --with-http_mp4_module \
    --with-http_realip_module \
    --with-openssl=/tmp/${openssl_ver} \
    --with-http_ssl_module \
    --with-http_v2_module \
    --with-stream \
    --with-stream_realip_module \
    --with-stream_ssl_module \
    --with-stream_ssl_preread_module \
    --with-zlib=/tmp/zlib-1.2.11 \
    --with-pcre=/tmp/${pcre_ver} \
    --with-cc-opt='-O3 -pipe -Wall -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector --param=ssp-buffer-size=4 -m64 -mtune=generic -fPIC' \
    || { echo "configure ${nginx_ver} failed!";exit 1;}
}

install_nginx(){
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
    uninstall_old_nginx
    mkdir -p /var/cache/nginx
    make install || exit $?
    echo "Download nginx from https://pan.0db.org:65000/dep/nginx to /etc/rc.d/init.d/nginx"
    curl --continue-at - --speed-limit 10240 --speed-time 5 --retry 3 --progress-bar --location "https://pan.0db.org:65000/dep/nginx" -o /etc/rc.d/init.d/nginx || exit 1
    chown root:root /etc/rc.d/init.d/nginx && chmod 755 /etc/rc.d/init.d/nginx
    chown root:root /usr/sbin/nginx && chmod 755 /usr/sbin/nginx
    chkconfig --add nginx
    chkconfig nginx on
    rm -f /etc/nginx/*.default
    service nginx start && echo 'completed'
}

clean_tmp(){
    rm -rf "/tmp/${openssl_ver}"
    rm -rf "/tmp/zlib-1.2.11"
    rm -rf "/tmp/${pcre_ver}"
    rm -rf "/tmp/${fancyindex_ver}"
    rm -rf "/tmp/${nginx_ver}"
}

_checkPrivilege
os_ver=$(_sysVer)
if [ "${os_ver}" != 6 ]; then
    echo "This script can only be used in centos 6."
    exit 1
fi
[ "$1" == "index" ] && { install_fancyindex; exit;}
[ "$1" == "config" ] && { download_openssl && download_zlib && download_pcre && cd /tmp/${nginx_ver} && configure_nginx; exit;}

echo
echo "openssl          : ${openssl_ver}"
echo "nginx            : ${nginx_ver}"
echo "pcre             : ${pcre_ver}"
echo "fancyindex       : ${fancyindex_ver}"
echo
echo 'You can execute "nginx.sh index" and install the fancyindex module separately'
read -r -n 1 -p "Are you sure you want to continue? [y/n]" input
case $input in
    "y")
        echo
        yum -y install gcc gcc-c++ perl make pcre-devel openssl-devel zlib-devel ca-certificates || exit 1
        clean_tmp
        download_openssl
        download_zlib
        download_pcre
        install_nginx
        install_fancyindex
        ;;
    *)
        echo
        exit 1
        ;;
esac
