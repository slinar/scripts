自用的一些一键安装脚本
===========================
所有脚本只在 centos6.10 上测试过, 如需在其他版本的系统上使用请自行测试修改

没啥技术含量, 写的比较烂但是能用, 使用前请确保网络连接正常

如有错误, 欢迎反馈!
****
|文件|描述|
|---|---
|python3.7.sh|一键安装openssl-1.1.1d和python-3.7
|openssh.sh|一键安装openssl-1.1.1d和openssh-8.1p1
|nginx.sh|一键安装nginx(可选openssl版本)
|nginx|centos 6上的nginx服务脚本
|nginx.conf|ngx-fancyindex示例配置

nginx.sh中使用了自己的文件服务器,不得不吐槽不挂代理的情况下连接github很不稳定

**注意: 使用openssh.sh脚本的时候建议放在screen(或者类似的其他工具)中执行, 防止升级过程中意外断开ssh连接导致脚本执行终止升级失败.**
