一些自用脚本
===========================

|文件|描述|适用OS版本|备注|
|---|---|---|---|
|openssh_el6.sh|openssh升级脚本|Centos 6|使用libressl库
|openssh.sh|openssh升级脚本|Centos 6+/Rocky Linux)|使用openssl库
|nginx.sh|nginx安装脚本|Centos 6
|curl.sh|curl升级脚本|Centos 6+/Rocky Linux)|为Centos 6/7提供http2&tls1.3支持
|nginx|nginx服务脚本|Centos 6

使用前请确保网络连接正常, 如需在其他版本的系统上使用请自行测试修改, 如果错误欢迎提交Issues

* openssh可以不依赖openssl或libressl编译(Line 13: without_openssl=yes)
* 为了提高稳定性和减少对现有系统环境的影响，openssh静态链接openssl

**注意: 使用openssh.sh脚本的时候建议放在screen(或者类似的其他工具)中执行, 防止升级过程中意外断开(理论上不会断开)ssh连接导致脚本执行终止升级失败.**
