
from selenium.webdriver.chrome.service import Service
import requests

def test_or(attack, url, domain):  # Attack 객체를 첫 번째 인자로 받음+ name = 요청한 페이지의 url 도메인 
    #main에서 생성된 WebDriver 객체를 이용하여 페이지 이동 (redirect 페이지로 이동)
    attack.driver.get(url)

    #리다이렉트 이후의 response 가져와서 url 가져오기
    redirect_url = attack.driver.current_url

    # 만약 현재 URL이 처음에 요청한 URL과 다르고, '/'로 시작하지 않고 주어진 'name'으로 시작하지 않는 경우 (=다른 도메인으로 이동하는 경우)
    if  redirect_url != url and not url.startswith('/') and not url.startswith(domain):
        # Open redirection이 감지된 경우
        print("Open redirection was detected")
    else:
        # Open redirection이 아닌 경우
        print("No open redirection")

    response = requests.get(url, allow_redirects=True)

    # 만약 응답의 상태 코드가 리다이렉트 코드인 경우(301, 302, 303, 307, 308)
    if response.status_code in [301, 302, 303, 307, 308]:
        # 응답 헤더에서 'Location'을 가져와 리다이렉트된 URL을 얻음
        redirect_header = response.headers.get('Location')

        # 만약 리다이렉트된 URL이 존재하고, '/'로 시작하지 않고 주어진 'name'으로 시작하지 않는 경우
        if redirect_header and not redirect_header.startswith('/') and not redirect_url.startswith(domain):
            # Open redirection이 감지된 경우
            print("Open redirection was detected")
        else:
            # Open redirection이 아닌 경우
            print("No open redirection")
