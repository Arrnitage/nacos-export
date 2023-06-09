import requests
import sys

def get_auth_token(target: str, username: str, password: str) -> str:
    token = ""
    path = "/v1/auth/users/login"
    url = target + path
    headers = {
        'Sec-Ch-Ua': '"Not;A=Brand";v="99", "Chromium";v="106"',
        'Accept': 'application/json, text/plain, */*',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Sec-Ch-Ua-Mobile': '?0',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.5249.91 Safari/537.36',
        'Sec-Ch-Ua-Platform': '"macOS"',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-Mode': 'cors',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh;q=0.9',
    }
    data = {
        'username': username,
        'password': password,
    }
    resp = requests.post(url, headers=headers, data=data)
    resp_dict = resp.json()
    token = resp_dict.get("accessToken")
    return token


def get_namespaces(target: str, token: str) -> list:
    namespace_id = []
    path = "/v1/console/namespaces"
    url = target + path
    headers = {
        'Sec-Ch-Ua': '"Not;A=Brand";v="99", "Chromium";v="106"',
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'X-Requested-With': 'XMLHttpRequest',
        'Sec-Ch-Ua-Mobile': '?0',
        'Authorization': '{"accessToken":"%s":18000,"globalAdmin":false}' % token,
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.5249.91 Safari/537.36',
        'Sec-Ch-Ua-Platform': '"macOS"',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Dest': 'empty',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh;q=0.9',
    }
    params = {
        'accessToken': token,
        'namespaceId': '',
    }
    resp = requests.get(url, headers=headers, params=params)
    resp_dict = resp.json()
    namespace_id = [item['namespace'] for item in resp_dict['data']]
    return namespace_id


def dump_config_content(target: str, namespaces: list, token: str, count: int = 100):
    path = '/v1/cs/configs'
    url = target + path
    headers = {
        'Sec-Ch-Ua': '"Not;A=Brand";v="99", "Chromium";v="106"',
        'Accept': 'application/json, text/plain, */*',
        'Accesstoken': token,
        'Sec-Ch-Ua-Mobile': '?0',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.5249.91 Safari/537.36',
        'Sec-Ch-Ua-Platform': '"macOS"',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Dest': 'empty',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh;q=0.9',
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
        resp = requests.get(url, headers=headers, params=params)
        resp_dict = resp.json()
        for item in resp_dict['pageItems']:
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

    URL: like this https://127.0.0.1/some_path/, split at /v1
    COUNT: is optional, set max number.
    """.format(script=name))


if __name__ == '__main__':
    if len(sys.argv) < 3:
        usage(sys.argv[0])
        exit()

    target = sys.argv[1].rstrip('/')
    username = sys.argv[2]
    password = sys.argv[3]

    token = get_auth_token(target, username, password)
    namespaces = get_namespaces(target, token)
    dump_config_content(target, namespaces, token)