# pip install mitmproxy selenium webdriver_manager psutil

# 인증서 추가 방법 WIN
# 1. %USERPROFILE%\.mitmproxy\mitmproxy-ca-cert.cer 실행 (안나오면 프록시랑 스크립트 실행시켜보고 재부팅)
# 2. 인증서 설치 -> 로컬 컴퓨터 -> 모든인증서를 다음 저장소에 저장
# 3. 신뢰할 수 있는 루트 인증 기관 -> 마침

# 인증서 추가 방법 MAC
# 1. 프록시 실행시킨 상태로  http://mitm.it/ 접속
# 2. 애플클릭하고 설치 OR
# sudo security add-trusted-cert -d -r trustRoot -p ssl -k /Library/Keychains/System.keychain $HOME/.mitmproxy/mitmproxy-ca-cert.pem
# 3. command + space누르고 키체인 검색
# 4. mitmproxy 인증서 더블클릭 후 상단의 신뢰 클릭
# 5. 이 인증서 사용시: 시스템초기설정사용 -> 항상신뢰 로 변경

# http사이트의 경우 주소창에서 s 지워줘야함....보안업데이트 싫어.... -> 스크립트먼저 실행하고 실행하면 안나온다는 소문이...


import subprocess
import threading
import time
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
import psutil
import DB_util
from USER_INPUT import scan_url

time.sleep(5)
print("==========Fuzzing Start==========")
conn = DB_util.connect_DB()


def process_kill(name):
    """중복 실행중인 프로세스 종료"""
    for proc in psutil.process_iter():
        if proc.name() == name:
            proc.kill()


process_kill("mitmproxy")

""" 웹인터페이스사용
# mitmproxy 서버 실행 함수
def run_mitmproxy():
    subprocess.call(
        [
            "mitmweb",  # 웹 인터페이스 실행
            "-s",  # 사용할 스크립트 지정
            "PROXY_mitmproxy_script.py",  # 사용할 스크립트
            "--web-port",  # 인터페이스 실행포트(감시포트)
            "8081",
            "--mode",  # 작동모드설정
            "regular",  # 모든 패킷 중계
            "--listen-port",  # 감시할 네트워크 포트(프록시 포트)
            "8080",
            "--showhost",  # 호스트이름 보여줌
        ]
    )
"""


def run_mitmproxy():
    process = subprocess.Popen(
        [
            "mitmdump",  # CLI 인터페이스 실행
            "-s",  # 사용할 스크립트 지정
            "PROXY_mitmproxy_script.py",  # 사용할 스크립트
            "--mode",  # 작동모드설정
            "regular",  # 모든 패킷 중계
            "--listen-port",  # 감시할 네트워크 포트(프록시 포트)
            "8080",
            "--showhost",  # 호스트이름 보여줌
        ],
        stdout=subprocess.PIPE,  # 표준 출력을 파이프로 리다이렉션
        stderr=subprocess.DEVNULL,  # 표준 에러 출력 무시
    )

    # 표준 출력에서 "WF-log:"  포함하는 라인만 필터링
    for line in process.stdout:
        try:
            line_str = line.decode("utf-8")  # UTF-8로 디코딩 시도
        except UnicodeDecodeError:
            line_str = line.decode("cp949")  # UTF-8 디코딩 실패 시 다른 인코딩 사용

        if "WF-log:" in line_str:
            print(line_str, end="")


# Selenium을 사용하여 프록시 서버에 접속하는 함수
def run_selenium():
    time.sleep(10)  # mitmproxy가 시작되기를 기다림
    proxy = "localhost:8080"
    chrome_options = Options()  # 옵션 초기화
    chrome_options.add_argument("--start-maximized")  # 셀레니움 크기 최대화
    chrome_options.add_argument("--incognito")  # 시크릿모드
    # chrome_options.add_argument("--ignore-certificate-errors")  # 모든 인증서 오류 무시(필요시 사용)
    chrome_options.add_argument(f"--proxy-server=http://{proxy}")  # 프록시 지성
    # 로그 비활성화
    chrome_options.add_experimental_option("excludeSwitches", ["enable-logging"])
    # WebRTC 설정 비활성화
    chrome_options.add_argument("--disable-features=WebRtcHideLocalIpsWithMdns")
    driver = webdriver.Chrome(
        service=Service(ChromeDriverManager().install()), options=chrome_options
    )
    driver.get(scan_url)  # 시작화면

    # 페이지를 열어두고, 사용자가 직접 종료할 때까지 기다림
    while True:
        time.sleep(3)


# mitmproxy 스레드 실행
mitmproxy_thread = threading.Thread(target=run_mitmproxy)
mitmproxy_thread.start()

# Selenium 스레드 실행
selenium_thread = threading.Thread(target=run_selenium)
selenium_thread.start()

while True:
    time.sleep(1)
