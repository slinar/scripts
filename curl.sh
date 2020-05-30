#!/bin/bash
openssl_ver="openssl-1.1.1g"
nghttp2_ver="nghttp2-1.40.0"
curl_ver="curl-7.70.0"
pycurl_ver="pycurl-7.43.0.5"

install_zlib(){
    if [ -f /usr/local/zlib-1.2.11/lib/libz.a ];then
        echo "zlib-1.2.11 already exists!"
        return
    fi
    cd /tmp || exit 1
    if [ ! -f zlib-1.2.11.tar.gz ];then
        if ! wget --tries 3 --retry-connrefused -O zlib-1.2.11.tar.gz "https://zlib.net/zlib-1.2.11.tar.gz"; then
            rm -rf zlib-1.2.11.tar.gz
            echo "zlib-1.2.11.tar.gz download failed!"
            exit 1
        fi
    fi
    tar xzf zlib-1.2.11.tar.gz || exit 1
    cd zlib-1.2.11 || exit 1
    chmod 744 configure || exit 1
    ./configure --prefix=/usr/local/zlib-1.2.11 \
    || { echo "Failed to configure zlib!";exit 1;}
    make && make install
    local count
    count=$( grep -xc "/usr/local/zlib-1.2.11/lib" /etc/ld.so.conf )
    [ "${count}" -eq 0 ] && sed -i '$a\/usr/local/zlib-1.2.11/lib' /etc/ld.so.conf
    ldconfig
}

install_openssl(){
    if [ -f /usr/local/${openssl_ver}/lib/libssl.a ];then
        echo "${openssl_ver} already exists!"
        return
    fi
    if [ ! -f /etc/pki/tls/certs/ca-bundle.crt ];then
        echo "/etc/pki/tls/certs/ca-bundle.crt is not found!"
        exit 1
    fi
    cd /tmp || exit 1
    if [ ! -f ${openssl_ver}.tar.gz ];then
        if ! wget --tries 3 --retry-connrefused -O ${openssl_ver}.tar.gz "https://www.openssl.org/source/${openssl_ver}.tar.gz";then
            rm -rf ${openssl_ver}.tar.gz
            echo "${openssl_ver}.tar.gz download failed!"
            exit 1
        fi
    fi
    tar xzf ${openssl_ver}.tar.gz || exit 1
    cd ${openssl_ver} || exit 1
    chmod 744 config || exit 1
    ./config --prefix=/usr/local/${openssl_ver} --openssldir=/usr/local/${openssl_ver}/ssl -fPIC \
    || { echo "Failed to config openssl!";exit 1;}
    make && make install
    local count
    sed -i '/openssl-1/d' /etc/ld.so.conf
    count=$( grep -xc "/usr/local/${openssl_ver}/lib" /etc/ld.so.conf )
    [ "${count}" -eq 0 ] && sed -i '$a\/usr/local/'${openssl_ver}'/lib' /etc/ld.so.conf
    ldconfig
    rm -rf /usr/local/${openssl_ver}/ssl/certs
    ln -s /etc/pki/tls/certs /usr/local/${openssl_ver}/ssl/certs
    ln -s /etc/pki/tls/certs/ca-bundle.crt /usr/local/${openssl_ver}/ssl/cert.pem
}

install_nghttp2(){
    cd /tmp || exit 1
    if [ -f /usr/local/${nghttp2_ver}/lib/libnghttp2.a ]; then
        echo "${nghttp2_ver} already exists!"
        return
    fi
    if [ ! -f ${nghttp2_ver}.tar.bz2 ]; then
        if ! wget --tries 5 --retry-connrefused -O ${nghttp2_ver}.tar.bz2 "https://pan.0db.org/directlink/1/dep/${nghttp2_ver}.tar.bz2"; then
            rm -f ${nghttp2_ver}.tar.bz2
            echo "${nghttp2_ver}.tar.bz2 download failed!"
            exit 1
        fi
    fi
    tar jxf ${nghttp2_ver}.tar.bz2 || exit 1
    cd ${nghttp2_ver} || exit 1
    chmod 744 configure || exit 1
    export OPENSSL_LIBS=/usr/local/${openssl_ver}/lib/
    export ZLIB_LIBS=/usr/local/zlib-1.2.11/lib/
    ./configure --prefix=/usr/local/${nghttp2_ver} --enable-lib-only --disable-shared CFLAGS=-fPIC \
    || { echo "Failed to config nghttp2!";exit 1;}
    make && make install
    ls /usr/local/${nghttp2_ver}/lib/libnghttp2.a || exit 1
}

install_curl(){
    cd /tmp || exit 1
    if [ ! -f ${curl_ver}.tar.gz ]; then
        if ! wget --tries 5 --retry-connrefused -O ${curl_ver}.tar.gz "https://curl.haxx.se/download/${curl_ver}.tar.gz"; then
            rm -f ${curl_ver}.tar.gz
            echo "${curl_ver}.tar.gz download failed!"
            exit 1
        fi
    fi
    tar zxf ${curl_ver}.tar.gz || exit 1
    cd ${curl_ver} || exit 1
    chmod 744 configure || exit 1
    ./configure --prefix=/usr --enable-optimize --with-ssl=/usr/local/${openssl_ver} --with-zlib=/usr/local/zlib-1.2.11 --with-nghttp2=/usr/local/${nghttp2_ver} CFLAGS=-fPIC \
    || { echo "Failed to config curl!";exit 1;}
    make && make install
}

install_pycurl(){
    ls /usr/bin/curl-config || exit 1
    cd /tmp || exit 1
    if [ ! -f ${pycurl_ver}.tar.gz ]; then
        if ! wget --tries 5 --retry-connrefused -O ${pycurl_ver}.tar.gz "https://dl.bintray.com/pycurl/pycurl/${pycurl_ver}.tar.gz"; then
            rm -f ${pycurl_ver}.tar.gz
            echo "${pycurl_ver}.tar.gz download failed!"
            exit 1
        fi
    fi
    tar zxf ${pycurl_ver}.tar.gz || exit 1
    cd ${pycurl_ver} || exit 1
    python setup.py install --curl-config=/usr/bin/curl-config || { echo "pycurl installation failed!";exit 1;}
    curl --version && echo "completed!"
}

clean_tmp(){
    rm -rf /tmp/${openssl_ver}
    rm -rf /tmp/${nghttp2_ver}
    rm -rf /tmp/${curl_ver}
    rm -rf /tmp/${pycurl_ver}
}

echo
echo "openssl : ${openssl_ver}"
echo "nghttp2 : ${nghttp2_ver}"
echo "curl    : ${curl_ver}"
echo "pycurl  : ${pycurl_ver}"
echo
read -r -n 1 -p "Are you sure you want to continue? [y/n]" input
case $input in
    "y")
        echo
        yum -y install gcc gcc-c++ wget perl make python-devel
        clean_tmp
        install_zlib
        install_openssl
        install_nghttp2
        install_curl
        install_pycurl
        ;;
    *)
        echo
        exit 1
        ;;
esac
