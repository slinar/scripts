#!/bin/bash
openssl_ver="openssl-1.1.1d"
python_ver="3.7.6"
python_major=${python_ver:0:3}

install_openssl(){
    if [ -f /usr/local/${openssl_ver}/bin/openssl ];then
        echo "${openssl_ver} already exists!"
        return
    fi
    if [ ! -f /etc/pki/tls/certs/ca-bundle.crt ];then
        echo "/etc/pki/tls/certs/ca-bundle.crt is not found!"
        exit 1
    fi
    cd /tmp
    if [ ! -f ${openssl_ver}.tar.gz ];then
        wget https://www.openssl.org/source/${openssl_ver}.tar.gz
        if [ $? -ne 0 ];then
            rm -rf ${openssl_ver}.tar.gz
            echo "${openssl_ver}.tar.gz download failed!"
            exit 1
        fi
    fi
    tar xzf ${openssl_ver}.tar.gz
    [ $? -ne 0 ] && echo "${openssl_ver}.tar.gz Unpacking failed!" && exit 1
    cd ${openssl_ver}
    chmod u+x config
    ./config --prefix=/usr/local/${openssl_ver} --openssldir=/usr/local/${openssl_ver}/ssl -fPIC
    if [ $? -ne 0 ];then
        echo "Failed to config openssl!"
        exit 1
    fi
    make
    make install
    c=$( grep -x "/usr/local/${openssl_ver}/lib" /etc/ld.so.conf|wc -l )
    [ ${c} -eq 0 ] && sed -i '$a\/usr/local/'${openssl_ver}'/lib' /etc/ld.so.conf
    ldconfig
    rm -rf /usr/local/${openssl_ver}/ssl/certs
    ln -s /etc/pki/tls/certs /usr/local/${openssl_ver}/ssl/certs
    ln -s /etc/pki/tls/certs/ca-bundle.crt /usr/local/${openssl_ver}/ssl/cert.pem
}

install_python(){
    cd /tmp
    if [ ! -f Python-${python_ver}.tgz ];then
        wget https://npm.taobao.org/mirrors/python/${python_ver}/Python-${python_ver}.tgz
        if [ $? -ne 0 ];then
            rm -rf Python-${python_ver}.tgz
            echo "Python-${python_ver}.tgz download failed!"
            exit 1
        fi
    fi
    tar xzf Python-${python_ver}.tgz
    [ $? -ne 0 ] && echo "Python-${python_ver}.tgz Unpacking failed!" && exit 1
    cd Python-${python_ver}
    chmod u+x configure
    ./configure --prefix=/usr/local/python${python_major} --enable-shared CFLAGS=-fPIC --with-openssl=/usr/local/${openssl_ver}
    if [ $? -ne 0 ];then
        echo "Failed to configure python${python_ver}!"
        exit 1
    fi
    make
    make install
    c=$( grep -x "/usr/local/python${python_major}/lib" /etc/ld.so.conf|wc -l )
    [ ${c} -eq 0 ] && sed -i '$a\/usr/local/python'${python_major}'/lib' /etc/ld.so.conf
    ldconfig
    ln -s /usr/local/python${python_major}/bin/python${python_major} /usr/bin/python${python_major}
    ln -s /usr/local/python${python_major}/bin/pip${python_major} /usr/bin/pip${python_major}
    pip${python_major} install --upgrade pip
    python${python_major} -c 'import ssl; print(ssl.OPENSSL_VERSION); print(ssl.get_default_verify_paths())'
}

echo
echo "openssl = ${openssl_ver}"
echo "python = Python-${python_ver}"
echo "install path = /usr/local/python${python_major}"
echo
read -r -n 1 -p "Are you sure you want to continue? [y/n]" input
case $input in
    "y")
        yum -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-6.noarch.rpm
        yum clean all && yum makecache
        yum -y install gcc wget perl make pam-devel
        yum -y install zlib-devel bzip2-devel readline-devel sqlite-devel openssl-devel ncurses-devel xz-devel gdbm-devel libffi-devel
        install_openssl
        install_python
        ;;
    *)
        exit 1
        ;;
esac
