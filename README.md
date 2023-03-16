# NACOS EXPORT

通过账号密码进行nacos配置内容导出。

## Use

``` bash
$ python3 nacos-export.py

 ______________
< Nacos Export >         @Author: Arm!tage
 --------------
        \   ^__^
         \  (oo)\_______
            (__)\       )\/\
                ||----w |         
                ||     ||

Usage:
    python3 nacos-export.py <URL> <USERNAME> <PASSWORD> [COUNT]

    URL: like this https://127.0.0.1/some_path/, split at /v1
    COUNT: is optional, set max number.


python3 nacos-export.py http://127.0.0.1 nacos nacos
```

