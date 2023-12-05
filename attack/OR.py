from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
import requests
from main import Attack # main.py - Attack 클래스를 임포트

def test_or(attack, url, name):  # Attack 객체를 첫 번째 인자로 받음
    # 이미 생성된 WebDriver 객체를 이용하여 페이지 이동
    attack.driver.get(url)

    # 현재 URL 가져오기
    current_url = attack.driver.current_url

    # 만약 현재 URL이 처음에 요청한 URL과 다르고, '/'로 시작하지 않고 주어진 'name'으로 시작하지 않는 경우 (=다른 도메인으로 이동하는 경우)
    if current_url != url and not current_url.startswith('/') and not current_url.startswith(name):
        # Open redirection이 감지된 경우
        print("Open redirection was detected")
    else:
        # Open redirection이 아닌 경우
        print("No open redirection")

    # requests 라이브러리를 사용하여 HTTP 헤더를 통한 리다이렉션 감지
    response = requests.get(url, allow_redirects=False)

    # 만약 응답의 상태 코드가 리다이렉트 코드인 경우(301, 302, 303, 307, 308)
    if response.status_code in [301, 302, 303, 307, 308]:
        # 응답 헤더에서 'Location'을 가져와 리다이렉트된 URL을 얻음
        redirect_url = response.headers.get('Location')

        # 만약 리다이렉트된 URL이 존재하고, '/'로 시작하지 않고 주어진 'name'으로 시작하지 않는 경우
        if redirect_url and not redirect_url.startswith('/') and not redirect_url.startswith(name):
            # Open redirection이 감지된 경우
            print("Open redirection was detected")