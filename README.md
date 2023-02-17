一些自用脚本
===========================

|文件|描述|适用OS版本|备注|
|---|---|---|---|
|openssh.sh|openssh升级脚本|RHEL 6+/CentOS 6+/Rocky Linux/AlmaLinux|使用openssl库
|curl.sh|curl升级脚本|RHEL 6+/CentOS 6+/Rocky Linux/AlmaLinux|为Centos 6/7提供http2&tls1.3支持
|build_nginx.sh|nginx构建脚本|Linux|手动构建nginx

使用前请确保网络连接正常, 如需在其他版本的系统上使用请自行测试修改, 如有错误欢迎提交Issues

* openssh可以不依赖openssl或libressl编译, 谨慎使用(Line 13: without_openssl=yes)
* 为了提高稳定性和减少对现有系统环境的影响, openssh静态链接openssl库

**注意: 使用openssh.sh脚本的时候建议放在screen(或者类似的其他工具)中执行, 防止升级过程中意外断开(理论上不会断开)ssh连接导致脚本执行终止升级失败.**
