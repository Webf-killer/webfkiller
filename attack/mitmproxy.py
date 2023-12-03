# pip install mitmproxy selenium webdriver_manager psutil

# 인증서 추가 방법
# 1. %USERPROFILE%\.mitmproxy\mitmproxy-ca-cert.cer 실행
# 2. 인증서 설치 -> 로컬 컴퓨터 -> 모든인증서를 다음 저장소에 저장
# 3. 신뢰할 수 있는 루트 인증 기관 -> 마침


import subprocess
import threading
import time
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
import psutil


def process_kill(name):
    """중복 실행중인 프로세스 종료"""
    for proc in psutil.process_iter():
        if proc.name() == name:
            proc.kill()


process_kill("mitmproxy")


# mitmproxy 서버 실행 함수
def run_mitmproxy():
    subprocess.call(
        [
            "mitmweb",  # 웹 인터페이스 실행
            "-s",  # 사용할 스크립트 지정
            "mitmproxy_script.py",  # 사용할 스크립트
            "--web-port",  # 인터페이스 실행포트(감시포트)
            "8081",
            "--mode",  # 작동모드설정
            "regular",  # 모든 패킷 중계
            "--listen-port",  # 감시할 네트워크 포트(프록시 포트)
            "8080",
            "--showhost",  # 호스트이름 보여줌
        ]
    )


# Selenium을 사용하여 프록시 서버에 접속하는 함수
def run_selenium():
    time.sleep(10)  # mitmproxy가 시작되기를 기다림
    proxy = "localhost:8080"
    chrome_options = Options()  # 옵션 초기화
    chrome_options.add_argument("--start-maximized")  # 셀레니움 크기 최대화
    chrome_options.add_argument("--incognito")  # 시크릿모드
    # chrome_options.add_argument("--ignore-certificate-errors")  # 모든 인증서 오류 무시(필요시 사용)
    chrome_options.add_argument(f"--proxy-server=http://{proxy}")  # 프록시 지성
    driver = webdriver.Chrome(
        service=Service(ChromeDriverManager().install()), options=chrome_options
    )
    driver.get("http://seku-assign.iptime.org:9999/")  # 시작화면
    # driver.get("http://example.com")  # 시작화면

    # 페이지를 열어두고, 사용자가 직접 종료할 때까지 기다림
    while True:
        time.sleep(3)


# mitmproxy 스레드 실행
mitmproxy_thread = threading.Thread(target=run_mitmproxy)
mitmproxy_thread.start()

# Selenium 스레드 실행
selenium_thread = threading.Thread(target=run_selenium)
selenium_thread.start()

# 데모를 위해 일정 시간 후 스크립트 종료 (필요에 따라 제거하거나 수정)
time.sleep(600)  # 예: 10분(600초) 동안 실행
