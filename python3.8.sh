#!/bin/bash
openssl_ver="openssl-1.1.1g"
python_ver="3.8.5"
python_major=${python_ver:0:3}

install_openssl(){
    if [[ -f /usr/local/${openssl_ver}/lib/libcrypto.a && -f /usr/local/${openssl_ver}/lib/libssl.a ]];then
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
    tar -zxf ${openssl_ver}.tar.gz || exit 1
    cd ${openssl_ver} || exit 1
    chmod 744 config || exit 1
    ./config --prefix=/usr/local/${openssl_ver} --openssldir=/usr/local/${openssl_ver}/ssl -fPIC no-shared \
    || { echo "Failed to config openssl!";exit 1;}
    make
    make install_sw
    mkdir -p /usr/local/${openssl_ver}/ssl
    ln -fs /etc/pki/tls/certs /usr/local/${openssl_ver}/ssl/certs
    ln -fs /etc/pki/tls/certs/ca-bundle.crt /usr/local/${openssl_ver}/ssl/cert.pem
}

install_python(){
    cd /tmp || exit 1
    if [ ! -f Python-${python_ver}.tgz ];then
        if ! wget --tries 3 --retry-connrefused -O Python-${python_ver}.tgz https://npm.taobao.org/mirrors/python/${python_ver}/Python-${python_ver}.tgz;then
            rm -rf Python-${python_ver}.tgz
            echo "Python-${python_ver}.tgz download failed!"
            exit 1
        fi
    fi
    tar -zxf Python-${python_ver}.tgz || { echo "Python-${python_ver}.tgz Unpacking failed!";exit 1;}
    cd Python-${python_ver} || { echo "cd Python-${python_ver} failed!";exit 1;}
    chmod 744 configure
    ./configure --prefix=/usr/local/python${python_major} CFLAGS=-fPIC --with-openssl=/usr/local/${openssl_ver} \
    || { echo "Failed to configure python${python_ver}!";exit 1;}
    make || { echo "make Python-${python_ver} failed!";exit 1;}
    [ -e /tmp/site-packages ] && rm -rf /tmp/site-packages 
    [ -d /usr/local/${python_major}/lib/${python_major}/site-packages ] && mv -f /usr/local/${python_major}/lib/${python_major}/site-packages /tmp
    make install || { echo "make install Python-${python_ver} failed!";exit 1;}
    [ -d /tmp/site-packages ] && rm -rf /usr/local/${python_major}/lib/${python_major}/site-packages && mv -f /tmp/site-packages /usr/local/${python_major}/lib/${python_major}
    ln -fs /usr/local/python${python_major}/bin/python${python_major} /usr/bin/python${python_major}
    ln -fs /usr/local/python${python_major}/bin/pip${python_major} /usr/bin/pip${python_major}
    pip${python_major} install --upgrade pip
    python${python_major} -c 'import ssl; print(ssl.OPENSSL_VERSION); print(ssl.get_default_verify_paths())' && echo "completed"
}

clean_tmp(){
    rm -rf /tmp/${openssl_ver}
    rm -rf /tmp/Python-${python_ver}
}

echo
echo "openssl      : ${openssl_ver}"
echo "python       : Python-${python_ver}"
echo "install_path : /usr/local/python${python_major}"
echo
read -r -n 1 -p "Are you sure you want to continue? [y/n]" input
case $input in
    "y")
        echo
        yum -y install gcc gcc-c++ wget perl make
        yum -y install zlib-devel bzip2-devel readline-devel sqlite-devel openssl-devel ncurses-devel xz-devel gdbm-devel libffi-devel
        clean_tmp
        install_openssl
        install_python
        ;;
    *)
        echo
        exit 1
        ;;
esac
