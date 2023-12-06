import requests
import urllib.parse

class OpenRedirection: 

    def __init__(self, driver):  
        self.driver = driver 
    
    def is_relative(self, redirect_url):
        # 상대 경로 여부를 확인하는 함수
        return not bool(urllib.parse.urlparse(redirect_url).netloc)
    
    def check_redirection(self, url, redirected_url):
        domain = urllib.parse.urlparse(url).netloc  # 리다이렉트 요청 URL의 도메인 추출
        if redirected_url != url and not self.is_relative(redirected_url) and not redirected_url.startswith(domain):
            # Open redirection이 감지된 경우
            print("Open redirection detected to: " + url)
            # logging.info("Open redirection detected to: " + url)
        else: print("NO Open redirection")

    def test_or(self, request, response):
        url = request.url
        
        # WebDriver를 이용하여 리다이렉트 탐지
        current_url = self.driver.current_url
        self.driver.get(url)
        redirect_url = self.driver.current_url
        self.check_redirection(url, redirect_url)
        
        # 만약 응답의 상태 코드가 리다이렉트 코드인 경우(301, 302, 303, 307, 308)
        if response.status_code in [301, 302, 303, 307, 308] and 'Location' in response.headers:
            # 응답 헤더에서 'Location'을 가져와 리다이렉트된 URL을 얻음
            location_url = response.headers.get('Location')
            self.check_redirection(url, location_url)
