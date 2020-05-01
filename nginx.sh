#!/bin/bash

openssl_ver="openssl-1.1.1g"
pcre_ver="pcre-8.44"
nginx_ver="nginx-1.18.0"
fancyindex_ver="ngx-fancyindex-0.4.4"

download_zlib(){
    cd /tmp || exit 1
    if [ ! -f zlib-1.2.11.tar.gz ];then
        if ! wget --tries 3 --retry-connrefused -O zlib-1.2.11.tar.gz "https://zlib.net/zlib-1.2.11.tar.gz"; then
            rm -f zlib-1.2.11.tar.gz
            echo "zlib-1.2.11.tar.gz download failed!"
            exit 1
        fi
    fi
    tar xzf zlib-1.2.11.tar.gz || exit 1
    cd zlib-1.2.11 || exit 1
    chmod 744 configure || exit 1
}

download_openssl(){
    cd /tmp || exit 1
    if [ ! -f ${openssl_ver}.tar.gz ];then
        if ! wget --tries 3 --retry-connrefused -O ${openssl_ver}.tar.gz "https://www.openssl.org/source/${openssl_ver}.tar.gz"; then
            rm -f ${openssl_ver}.tar.gz
            echo "${openssl_ver}.tar.gz download failed!"
            exit 1
        fi
    fi
    tar xzf ${openssl_ver}.tar.gz || exit 1
    cd ${openssl_ver} || exit 1
    chmod 744 config || exit 1
}

download_pcre(){
    cd /tmp || exit 1
    if [ ! -f ${pcre_ver}.tar.gz ];then
        if ! wget --tries 3 --retry-connrefused -O ${pcre_ver}.tar.gz "https://ftp.pcre.org/pub/pcre/${pcre_ver}.tar.gz"; then
            rm -f ${pcre_ver}.tar.gz
            echo "${pcre_ver}.tar.gz download failed!"
            exit 1
        fi
    fi
    tar xzf ${pcre_ver}.tar.gz || exit 1
    cd ${pcre_ver} || exit 1
    chmod 744 configure || exit 1
}

install_fancyindex(){
    cd /tmp || exit 1
    if [ ! -f ${fancyindex_ver}.tar.gz ];then
        if ! wget --tries 3 --retry-connrefused -O ${fancyindex_ver}.tar.gz "https://pan.0db.org/directlink/1/dep/${fancyindex_ver}.tar.gz"; then
            rm -f ${fancyindex_ver}.tar.gz
            echo "${fancyindex_ver}.tar.gz download failed!"
            exit 1
        fi
    fi
    tar xzf ${fancyindex_ver}.tar.gz || exit 1
    cd ${fancyindex_ver} || exit 1
    cd /tmp/${nginx_ver} || exit 1
    echo "src version: $(grep NGINX_VERSION src/core/nginx.h|grep -vE 'grep|/'|awk '{print $3}')"
    echo -n "current " && nginx -v
    read -r -n 1 -p "Are you sure you want to continue? [y/n]" input
    [ "${input}" != "y" ] && echo && exit 1
    ./configure --with-compat --add-dynamic-module=/tmp/${fancyindex_ver} || { echo "ERROR: configure ${fancyindex_ver} with ${nginx_ver}";exit 1;}
    make modules || { echo "ERROR: make ${fancyindex_ver} with ${nginx_ver}";exit 1;}
    [ ! -f objs/ngx_http_fancyindex_module.so ] && echo "ERROR: /tmp/${nginx_ver}/objs/ngx_http_fancyindex_module.so not found!" && exit 1
    mkdir -p /usr/lib64/nginx/modules || exit 1
    cp -f objs/ngx_http_fancyindex_module.so /usr/lib64/nginx/modules/ngx_http_fancyindex_module.so || exit 1
    local count
    count=$(grep load_module /etc/nginx/nginx.conf|grep '/usr/lib64/nginx/modules/ngx_http_fancyindex_module.so'|grep -cv '#')
    [ "${count}" -eq 0 ] && sed -i '1iload_module /usr/lib64/nginx/modules/ngx_http_fancyindex_module.so;' /etc/nginx/nginx.conf
    nginx -t && service nginx reload
}

uninstall_old_nginx(){
    [ -d /etc/nginx ] && mv /etc/nginx /etc/nginx_bak
    yum -y remove nginx
    [ -d /etc/nginx_bak ] && mv /etc/nginx_bak /etc/nginx
    if nginx -v; then
        if service nginx status; then
            service nginx stop
        else
            nginx -s stop > /dev/null 2>&1
        
        fi
    fi
    chkconfig --del nginx
    rm -f /var/run/nginx.pid
    rm -f /var/lock/subsys/nginx
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
    --with-cc-opt='-O2 -pipe -Wall -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector --param=ssp-buffer-size=4 -m64 -mtune=generic -fPIC' \
    || { echo "configure ${nginx_ver} failed!";exit 1;}
}

install_nginx(){
    cd /tmp || exit 1
    if [ ! -f ${nginx_ver}.tar.gz ]; then
        if ! wget --tries 3 --retry-connrefused -O ${nginx_ver}.tar.gz "https://nginx.org/download/${nginx_ver}.tar.gz"; then
            rm -f ${nginx_ver}.tar.gz
            echo "${nginx_ver}.tar.gz download failed!"
            exit 1
        fi
    fi
    tar xzf ${nginx_ver}.tar.gz || exit 1
    cd ${nginx_ver} || exit 1
    chmod 744 configure || exit 1
    [ -f /var/cache/nginx ] && rm -f /var/cache/nginx
    mkdir -p /var/cache/nginx
    useradd -d /var/cache/nginx -s /sbin/nologin -c 'nginx user' nginx
    configure_nginx
    make || exit $?
    uninstall_old_nginx
    mkdir -p /var/cache/nginx
    make install || exit $?
    wget --tries 3 --retry-connrefused -O /etc/rc.d/init.d/nginx "https://pan.0db.org/directlink/1/dep/nginx" || exit 1
    chown root:root /etc/rc.d/init.d/nginx && chmod 755 /etc/rc.d/init.d/nginx
    chkconfig --add nginx
    chkconfig nginx on
    rm -f /etc/nginx/*.default
    service nginx start && echo "completed!"
}

clean_tmp(){
    rm -rf "/tmp/${openssl_ver}"
    rm -rf "/tmp/zlib-1.2.11"
    rm -rf "/tmp/${pcre_ver}"
    rm -rf "/tmp/${fancyindex_ver}"
    rm -f "/tmp/pax_global_header"
}

[ "$1" == "index" ] && { install_fancyindex; exit $?;}

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
        yum -y install gcc gcc-c++ perl make pcre-devel openssl-devel zlib-devel
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
