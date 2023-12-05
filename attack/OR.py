import requests
from bs4 import BeautifulSoup
import urllib.parse
import re

class OpenRedirection: 

    def __init__(self, driver):  
        self.driver = driver 

    def test_or(self, request, response):
        url = request.url
        domain = urllib.parse.urlparse(url).netloc

        # WebDriver를 이용하여 리다이렉트 탐지
        self.driver.get(url)
        redirect_url = self.driver.current_url
        #웹 드라이버가 현재 접근한 URL (self.driver.current_url)과 처음에 요청한 URL (url)이 동일한지 비교하여 리다이렉트를 감지
        #상대 경로로 시작하는지 (redirect_url.startswith('/'))도 확인
        #리다이렉트가 동일한 도메인 내부나 동일한 웹 페이지 내부로 이루어진 것이 아닌지를 확인
        if  redirect_url != url and not redirect_url.startswith('/') and not redirect_url.startswith(domain):
            print("WebDriver-based open redirection was detected")
        else:
            print("No WebDriver-based open redirection")



        # 클라이언트 측 리다이렉트 탐지
        
        redirect_url = response.url
        if  redirect_url != url and not redirect_url.startswith('/') and not redirect_url.startswith(domain):
            print("Client-side open redirection was detected")
        else:
            print("No client-side open redirection")

        # 추가한 부분
        soup = BeautifulSoup(response.text, 'html.parser')

        # HTML meta 태그를 사용하는 리다이렉트 감지
        # HTML 문서에서 <meta http-equiv="refresh" content="..."> 형태의 태그를 찾아서 리다이렉트를 감지
        # 웹 페이지를 새로 고침하거나 다른 페이지로 리다이렉트시키는 역할
        meta_refresh = soup.find('meta', attrs={'http-equiv': re.compile("^refresh$", re.I)})
        if meta_refresh and 'content' in meta_refresh.attrs:
            print("Client-side redirection (via meta tag) detected. Content:", meta_refresh['content'])

        # JavaScript를 사용하는 리다이렉트 감지
        # window.location 객체를 사용하여 리다이렉트를 수행하는 경우
        scripts = soup.find_all('script')
        for script in scripts:
            if 'window.location' in script.text:
                print("Client-side redirection (via JavaScript) detected in script:", script.text)


        # 서버 측 리다이렉트 확인 (수정)
        server_side_redirect_detected = False

        # HTTP 상태 코드 3xx와 함께 'Location' 헤더를 포함하는지 확인
        if response.status_code in [301, 302, 303, 307, 308] and 'Location' in response.headers:
            redirect_header = response.headers.get('Location')
            if redirect_header and not redirect_header.startswith('/') and not redirect_header.startswith(domain):
                print("Server-side redirection detected to:", response.headers['Location'])
                server_side_redirect_detected = True

        # 'Refresh' 헤더를 사용하는 리다이렉트 감지 (추후 추가 예정)
        # if 'Refresh' in response.headers:
        #     print("Server-side redirection (via Refresh header) detected. Content:", response.headers['Refresh'])
        #     server_side_redirect_detected = True

        if not server_side_redirect_detected:
            print("server-side redirection was not detected")

