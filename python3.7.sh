#!/bin/bash
yum -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-6.noarch.rpm
yum clean all && yum makecache
yum -y install gcc wget perl make pam-devel
yum -y install zlib-devel bzip2-devel readline-devel sqlite-devel openssl-devel ncurses-devel xz-devel gdbm-devel libffi-devel
openssl_ver="openssl-1.1.1d"
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
	cd ${openssl_ver}
	chmod u+x config
    ./config --prefix=/usr/local/${openssl_ver} --openssldir=/usr/local/${openssl_ver}/ssl -fPIC
	if [ $? -ne 0 ];then
	    echo "Failed to config openssl!"
		exit 1
	fi
    make
    make install
    sed -i '$a\/usr/local/'${openssl_ver}'/lib' /etc/ld.so.conf
    ldconfig
    rm -rf /usr/local/${openssl_ver}/ssl/certs
    ln -s /etc/pki/tls/certs /usr/local/${openssl_ver}/ssl/certs
    ln -s /etc/pki/tls/certs/ca-bundle.crt /usr/local/${openssl_ver}/ssl/cert.pem
}

install_python(){
    cd /tmp
    if [ ! -f Python-3.7.5.tgz ];then
        wget https://www.python.org/ftp/python/3.7.5/Python-3.7.5.tgz
		if [ $? -ne 0 ];then
		    rm -rf Python-3.7.5.tgz
			echo "Python-3.7.5.tgz download failed!"
			exit 1
		fi
    fi
	tar xzf Python-3.7.5.tgz
    cd Python-3.7.5
    chmod u+x configure
	./configure --prefix=/usr/local/python3.7 --enable-shared CFLAGS=-fPIC --with-openssl=/usr/local/${openssl_ver}
	if [ $? -ne 0 ];then
	    echo "Failed to configure python3.7!"
		exit 1
	fi
    make
    make install
    sed -i '$a\/usr/local/python3.7/lib' /etc/ld.so.conf
    ldconfig
    ln -s /usr/local/python3.7/bin/python3.7 /usr/bin/python3.7
    ln -s /usr/local/python3.7/bin/pip3.7 /usr/bin/pip3.7
	pip3.7 install --upgrade pip
	python3.7 -c 'import ssl; print(ssl.OPENSSL_VERSION)'
}

if [ -f /usr/local/python3.7/bin/python3.7 ];then
    echo "python3.7 already exists!"
    exit 1
fi
install_openssl
install_python
