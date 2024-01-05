import requests
import ast
import os
import binascii
import sys
import DB_util
import subprocess


conn = DB_util.connect_DB()

os_name = os.name
if os_name == "nt":  # 윈도우일경우
    py = "python"
    path = "\\"
else:
    py = "python3"
    path = "/"


def generate_random_hash():  # 4바이트 랜덤해쉬
    return binascii.hexlify(os.urandom(4)).decode()


# 포스트방식 요청 보내기
def send_custom_request_post(url, data, headers, random_hash, vul_type):
    response = requests.post(url, data=data, headers=headers)
    print_response(response, data, random_hash, vul_type)


# 겟방식 요청보내기
def send_custom_request_get(url, params, headers, random_hash, vul_type):
    response = requests.get(url, params=params, headers=headers)
    print_response(response, params, random_hash, vul_type)


# 출력관리 -> 스캐너로 넘길 수 있는 것들
def print_response(response, data, random_hash, vul_type):
    try:
        # 파라미터 갯수 계산
        parms_count = len(data)

        # Content-Length 계산
        body_size = None
        if response.headers.get("Content-Length"):
            try:
                body_size = int(response.headers.get("Content-Length"))
            except ValueError:
                body_size = 0
                pass
        time = int(response.elapsed.total_seconds())

        # 데이터베이스에 저장
        DB_util.save_modified_packet_composer_request(
            conn,
            vul_type,
            response.status_code,
            time,
            response.url,
            str(response.headers),
            random_hash,
            str(data),
            parms_count,
            body_size,
            response.text,
        )
    except Exception as e:
        print(f"데이터 저장 중 오류 발생: {e}")

    if os_name == "nt":  # 윈도우일때
        if vul_type == "Reflected":
            subprocess.Popen(
                f"{py} .{path}Scanner_ReflectedXSS.py {random_hash}",
                shell=False,
            )
        elif vul_type == "SQLi":
            subprocess.Popen(
                f"{py} .{path}Scanner_SQLi.py {random_hash}",
                shell=False,
            )
    else:
        if vul_type == "Reflected":
            subprocess.Popen(
                [py, f".{path}Scanner_ReflectedXSS.py", random_hash],
                shell=False,
            )
        elif vul_type == "SQLi":
            subprocess.Popen(
                [py, f".{path}Scanner_SQLi.py", random_hash],
                shell=False,
            )


def read_payloads(file_name):
    with open(file_name, "r") as file:
        return [line.strip() for line in file]


# 보낼데이터 판단
num = sys.argv[1]
method, url, headers, raw_data = DB_util.get_proxy_request(conn, num)
method = method.lower()
url = url.split("?")[0]
headers = ast.literal_eval(headers)
raw_data = ast.literal_eval(raw_data)

vul_type = sys.argv[2]

payload_file = " ".join(sys.argv[3:])
test_payloads = read_payloads(payload_file)

# 키별로 테스트 페이로드 값을 적용
for key in raw_data.keys():
    for payload in test_payloads:
        modified_data = raw_data.copy()
        random_hash = generate_random_hash()
        modified_payload = f"webfkiller_{random_hash}_{payload}"
        modified_data[key] = modified_payload

        if method == "post":
            send_custom_request_post(url, modified_data, headers, random_hash, vul_type)
        elif method == "get":
            send_custom_request_get(url, modified_data, headers, random_hash, vul_type)
