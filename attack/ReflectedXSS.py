import mysql.connector
import requests
from urllib.parse import quote, urlencode
import hashlib
import random
import string
from bs4 import BeautifulSoup
import execjs

def generate_random_hash(length=8):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for i in range(length))

def send_reflected_xss_attack_from_mysql():
    # MITM Proxy 설정
    proxies = {
        "http": "http://localhost:8080",
        "https": "http://localhost:8080",
    }

    # MySQL에 연결
    connection = mysql.connector.connect(
        host="your_mysql_host",
        user="your_mysql_user",
        password="your_mysql_password",
        database="your_mysql_database"
    )

    cursor = connection.cursor()

    # 예시: 데이터베이스에서 URL, 데이터, reflectedxss 가져오기
    cursor.execute("SELECT url, data, reflectedxss FROM Request WHERE id = 1")
    row = cursor.fetchone()

    url = row[0]
    data = eval(row[1])  # 문자열 형태의 딕셔너리를 실제 딕셔너리로 변환
    reflectedxss_payload = row[2]

    connection.close()

    # 모든 파라미터에 대해 MD5 해시값을 생성하지 않고, 랜덤 해시값을 생성하여 적용
    for key in data:
        data[key] = f"{key}={generate_random_hash()}_{reflectedxss_payload}_yesgood'"

    try:
        # MITM Proxy를 통해 GET 요청 패킷 전송
        response_get = requests.get(url, headers=headers, proxies=proxies, verify=False)

        # MITM Proxy를 통해 POST 요청 패킷 전송
        response_post = requests.post(url, headers=headers, data=urlencode(data), proxies=proxies, verify=False)

        # 응답 출력
        print("GET Response:")
        print(response_get.text)

        print("\nPOST Response:")
        print(response_post.text)

        # 응답에서 자바스크립트 코드 추출
        extract_javascript_code(response_get.text)
        extract_javascript_code(response_post.text)

    except Exception as e:
        print(f"Error during request: {e}")

def extract_javascript_code(response_text):
    soup = BeautifulSoup(response_text, 'html.parser')
    script_tags = soup.find_all('script')

    for script_tag in script_tags:
        javascript_code = script_tag.string
        if javascript_code:
            detect_reflected_xss(javascript_code)

    # 이벤트 핸들러 안에 있는 자바스크립트 코드 추출
    event_handlers = soup.find_all(attrs={'on*': True})
    for event_handler in event_handlers:
        javascript_code = event_handler.get(event_handler.attrs['on*'])
        if javascript_code:
            detect_reflected_xss(javascript_code)

def detect_reflected_xss(javascript_code):
    try:
        # SyntaxError가 발생하면 Reflected XSS로 간주
        execjs.compile(javascript_code)
    except execjs.RuntimeError as e:
        print(f"Reflected XSS detected! Error message: {e}")
        print("Javascript Code:")
        print(javascript_code)

# 함수 호출
send_reflected_xss_attack_from_mysql()