#!/bin/bash

openssl_ver="openssl-1.1.1d"
pcre_ver="pcre-8.43"
nginx_ver="nginx-1.16.1"
fancyindex_ver="ngx-fancyindex-0.4.3"
fancyindex_theme_ver="Nginx-Fancyindex-Theme-0.1.7"

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

download_fancyindex(){
    cd /tmp || exit 1
    if [ ! -f ${fancyindex_ver}.tar.gz ];then
        if ! wget --tries 3 --retry-connrefused -O ${fancyindex_ver}.tar.gz "https://tang.0db.org/${fancyindex_ver}.tar.gz"; then
            rm -f ${fancyindex_ver}.tar.gz
            echo "${fancyindex_ver}.tar.gz download failed!"
            exit 1
        fi
    fi
    tar xzf ${fancyindex_ver}.tar.gz || exit 1
    cd ${fancyindex_ver} || exit 1
}

install_fancyindex_theme(){
    cd /tmp || exit 1
    if [ ! -f ${fancyindex_theme_ver}.tar.gz ]; then
        if ! wget --tries 3 --retry-connrefused -O ${fancyindex_theme_ver}.tar.gz "https://tang.0db.org/${fancyindex_theme_ver}.tar.gz"; then
            rm -f ${fancyindex_theme_ver}.tar.gz
            echo "${fancyindex_theme_ver}.tar.gz download failed!"
            exit 1
        fi
    fi
    tar xzf ${fancyindex_theme_ver}.tar.gz || exit 1
    cd ${fancyindex_theme_ver} || exit 1
    service nginx stop
    [ -d /usr/share/nginx/html ] && cp -rf /usr/share/nginx/html /tmp/html_bak
    mkdir /usr/share/nginx
    mv -f /etc/nginx/html /usr/share/nginx > /dev/null 2>&1
    wget --tries 3 --retry-connrefused -O /etc/nginx/nginx.conf "https://tang.0db.org/nginx.conf"
    cp -rf /tmp/${fancyindex_theme_ver} /usr/share/nginx/html/fancyindex
    service nginx start
    echo "fancyindex_theme example : http://yourIP:9666"
}

uninstall_old_nginx(){
    cp -rf /etc/nginx /tmp/nginx_bak
    yum -y remove nginx
    if service nginx status; then
        service nginx stop
    else
        pgrep nginx|xargs kill -9
        rm -f /var/run/nginx.pid
        rm -f /var/lock/subsys/nginx
        rm -f /var/run/nginx.lock
    fi
    chkconfig|grep nginx|grep -v grep && chkconfig --del nginx
    rm -rf /etc/nginx
    rm -f /usr/sbin/nginx
    rm -f /etc/rc.d/init.d/nginx
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
    --add-module=/tmp/${fancyindex_ver} \
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
    mkdir /var/cache/nginx
    useradd -d /var/cache/nginx -s /sbin/nologin -c 'nginx user' nginx
    configure_nginx
    make || exit $?
    uninstall_old_nginx
    make install || exit $?
    wget --tries 3 --retry-connrefused -O /etc/rc.d/init.d/nginx "https://tang.0db.org/nginx" || exit 1
    chown root:root /etc/rc.d/init.d/nginx && chmod 755 /etc/rc.d/init.d/nginx
    chkconfig --add nginx
    chkconfig nginx on
    service nginx start
    service nginx status || { echo "Start nginx failed! ";exit 1;}
}

clean_tmp(){
    rm -rf "/tmp/${openssl_ver}"
    rm -rf "/tmp/zlib-1.2.11"
    rm -rf "/tmp/${pcre_ver}"
    rm -rf "/tmp/${fancyindex_ver}"
    rm -f "/tmp/pax_global_header"
    rm -rf "/tmp/${fancyindex_theme_ver}"
}

echo
echo "openssl          : ${openssl_ver}"
echo "nginx            : ${nginx_ver}"
echo "pcre             : ${pcre_ver}"
echo "fancyindex       : ${fancyindex_ver}"
echo "fancyindex_theme : ${fancyindex_theme_ver}"
echo "Backup           : /etc/nginx --> /tmp/nginx_bak"
echo "Backup           : /usr/share/nginx/html --> /tmp/html_bak"
echo
read -r -n 1 -p "Are you sure you want to continue? [y/n]" input
case $input in
    "y")
        yum -y install gcc gcc-c++ perl make pcre-devel openssl-devel zlib-devel
        clean_tmp
        download_openssl
        download_zlib
        download_pcre
        download_fancyindex
        install_nginx
        install_fancyindex_theme
        ;;
    *)
        echo
        exit 1
        ;;
esac
