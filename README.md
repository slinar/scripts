自用的一些一键安装脚本
===========================
centos 6通用, 如需在其他版本的系统上使用请自行测试修改

没啥技术含量, 写的比较烂但是能用, 使用前请确保网络连接正常

如有错误, 欢迎反馈!
****
|文件|描述|
|---|---
|openssh.sh|openssh升级脚本(使用libressl,适用于Centos 6)
|openssh_el6_el7_el8.sh|openssh升级脚本(使用openssl,适用于Centos/Rocky Linux)
|nginx.sh|一键安装nginx(可选openssl版本)
|curl.sh|curl升级脚本(http2&tls1.3)
|nginx|centos 6上的nginx服务脚本


* openssh可以不依赖openssl或libressl编译(Line 13: without_openssl=yes)
* 为了提高稳定性和减少对现有系统环境的影响，openssh静态链接openssl

**注意: 使用openssh.sh脚本的时候建议放在screen(或者类似的其他工具)中执行, 防止升级过程中意外断开(理论上不会断开)ssh连接导致脚本执行终止升级失败.**
