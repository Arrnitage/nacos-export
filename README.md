# NACOS EXPORT

- ✅ 通过nacos账号密码导出配置
- ✅ 通过token导出配置
- ✅ 通过unauth/bypass导出配置
- ✅ 导出配置数量统计
- ✅ 通过sql导出配置

## Use

> 若要将将结果保存至文件，请通过重定向输出方式

```text
$ python3 nacos-export.py

 ______________
< Nacos Export >         @Author: Arm!tage
 --------------          @Version: v1.1.0
        \   ^__^
         \  (oo)\_______
            (__)\       )\/\
                ||----w |
                ||     ||

Usage:
    python3 nacos-export.py <URL> <USERNAME> <PASSWORD>
    python3 nacos-export.py <URL> <TOKEN>
    python3 nacos-export.py <URL> bypass|unauth
    python3 nacos-export.py <URL> sql

Example:
    python3 nacos-export.py http://localhost:8848/nacos nacos nacos
    python3 nacos-export.py http://localhost:8848/nacos eyJhbGciOiJIXXXXXXXXXXXX
    python3 nacos-export.py http://localhost:8848/nacos unauth
    python3 nacos-export.py http://localhost:8848/nacos sql
```
