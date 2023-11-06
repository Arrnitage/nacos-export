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
    resp = requests.post(url, headers=headers, data=data, proxies=proxy)
    resp_dict = resp.json()
    token = resp_dict.get("accessToken")
    return token


def get_namespaces(target: str, token: str) -> list:
    namespace_id = []
    path = "/v1/console/namespaces"
    url = target + path
    headers = {
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'Authorization': '{"accessToken":"%s":18000,"globalAdmin":false}' % token,
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.5249.91 Safari/537.36',
    }
    params = {
        'accessToken': token,
        'namespaceId': '',
    }
    resp = requests.get(url, headers=headers, params=params, proxies=proxy)
    resp_dict = resp.json()
    namespace_id = [item['namespace'] for item in resp_dict['data']]
    return namespace_id


def dump_config_content(target: str, namespaces: list, token: str, count: int = 100):
    path = '/v1/cs/configs'
    url = target + path
    headers = {
        'Accept': 'application/json, text/plain, */*',
        'Accesstoken': token,
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.5249.91 Safari/537.36',
    }
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
    python3 {script} <URL> <USERNAME> <PASSWORD> [COUNT]
    python3 {script} <URL> <USERNAME> <PASSWORD> [COUNT]

    Example:
        python3 {script} http://localhost:8848/nacos nacos nacos
        python3 {script} http://localhost:8848/nacos 2XnOEwXXXXXXXXXXXXXXXXtboYW
    COUNT: is optional, set max number.
    """.format(script=name))


if __name__ == '__main__':
    if len(sys.argv) < 3:
        usage(sys.argv[0])
        exit()

    target = sys.argv[1].rstrip('/')
    token = ""
    if len(sys.argv) == 3:
        token = get_auth_token(target, sys.argv[2], sys.argv[3])
    if len(sys.argv) == 2:
        token = sys.argv[2]
    
    namespaces = get_namespaces(target, token)
    dump_config_content(target, namespaces, token)