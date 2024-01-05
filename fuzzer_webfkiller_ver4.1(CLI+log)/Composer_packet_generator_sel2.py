import ast
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import time
import binascii
import os
import DB_util
import subprocess
import sys
from USER_INPUT import scan_url


conn = DB_util.connect_DB()

os_name = os.name
if os_name == "nt":  # 윈도우일경우
    py = "python"
    path = "\\"
else:
    py = "python3"
    path = "/"


def generate_random_hash():
    return binascii.hexlify(os.urandom(4)).decode()


# 셀레니움 설정
def setup_selenium():
    options = Options()
    options.add_argument("--headless")  # GUI 사용 안함
    # Chrome 드라이버의 로그 비활성화
    options.add_experimental_option("excludeSwitches", ["enable-logging"])
    # WebRTC 설정 비활성화
    options.add_argument("--disable-features=WebRtcHideLocalIpsWithMdns")
    options.add_argument("--log-level=OFF")  # 로그 레벨 off
    options.add_argument("--disable-logging")  # 로그를 남기지 않음!!!!!!

    driver = webdriver.Chrome(options=options)

    return driver


# 드라이버에 쿠키를 추가하는 함수
def add_cookies_to_driver(driver, cookie_str):
    driver.get(scan_url)  # 실제 사용할 도메인과 같아야 함.(쿠키설정을 위해)
    cookie_list = cookie_str.split("; ")
    for cookie in cookie_list:
        key, value = cookie.split("=", 1)
        driver.add_cookie({"name": key, "value": value})


def extract_cookies(headers):
    return headers.get("Cookie", "")


# 쿠키를 포함하여 커스텀 요청을 보내는 함수
def send_custom_request_selenium(driver, url, data, headers, random_hash):
    # 헤더 파일에서 쿠키 읽기
    cookies_str = extract_cookies(headers)
    add_cookies_to_driver(driver, cookies_str)  # 드라이버에 쿠키 추가

    # URL 생성 및 요청 보내기
    full_url = url + "?" + "&".join([f"{k}={v}" for k, v in data.items()])
    driver.get(full_url)
    time.sleep(0.5)  # 페이지가 로드될 때까지 기다림
    print_response_selenium(driver, data, random_hash)


# 응답 출력 함수
def print_response_selenium(driver, data, random_hash):
    DB_util.save_selenium_data(
        conn, driver.current_url, random_hash, data, driver.page_source
    )
    if os_name == "nt":  # 윈도우일경우
        subprocess.Popen(
            f"{py} .{path}Scanner_DomXSS.py {random_hash}",
            shell=False,
        )
    else:
        subprocess.Popen(
            [py, f".{path}Scanner_DomXSS.py", random_hash],
            shell=False,
        )


def read_payloads(file_name):
    with open(file_name, "r") as file:
        return [line.strip() for line in file]


# 셀레니움 드라이버 설정
driver = setup_selenium()


def read_payloads(file_name):
    with open(file_name, "r") as file:
        return [line.strip() for line in file]


# 요청 데이터 읽기 및 처리
num = sys.argv[1]
method, url, headers, raw_data = DB_util.get_proxy_request(conn, num)
url = url.split("?")[0]
headers = ast.literal_eval(headers)
raw_data = ast.literal_eval(raw_data)

payload_file = " ".join(sys.argv[2:])
test_payloads = read_payloads(payload_file)

# 키별로 테스트 페이로드 값을 적용
for key in raw_data.keys():
    for payload in test_payloads:
        modified_data = raw_data.copy()
        random_hash = generate_random_hash()
        modified_payload = f"webfkiller_{random_hash}_{payload}"
        modified_data[key] = modified_payload
        send_custom_request_selenium(driver, url, modified_data, headers, random_hash)

# 드라이버 종료
driver.quit()
