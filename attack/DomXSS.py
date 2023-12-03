import urllib.parse
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

#JavaScript는 웹 페이지의 DOM을 조작해 웹 페이지의 내용이나 구조를 동적으로 변경
#JavaScript 코드가 사용자로부터 받은 입력을 적절하게 처리하지 않고 그대로 DOM에 삽입하거나 실행
# = XSS 공격

def test_dom_based_xss(self, url):
        #XSS 공격에 사용할 페이로드들을 가져오기
        DOM_based_xss_payloads = self.get_data('payloads_Domxss', 'payload')
        #각 페이로드에 대해 
        for DOM_based_xss_payload in DOM_based_xss_payloads:
            #페이로드를 쿼리 문자열로 추가하여 새로운 URL을 만들기
            #공격 페이로드가 DOM에 삽입되는 부분
            manipulated_url_query = f"{url}?name=" + urllib.parse.quote(DOM_based_xss_payload)
            #새로운 URL로 웹 드라이버를 이용해 요청을 보내기
            print(f"Trying with payload: {DOM_based_xss_payload}")  # 페이로드를 출력
            self.driver.get(manipulated_url_query)
            self.check_payload_execution(url, 'name')

# 특정 엘리먼트의 존재 확인
def check_payload_execution(self, url, name):
        try:
            # 웹 페이지에서 특정 id를 가진 버튼을 찾아 클릭
            # 버튼 이름이 각각 다를것으로  추정? 
            # JavaScript 코드를 실행시키는 트리거 역할
            # JavaScript 코드는 클릭 이벤트를 처리하기 위해 DOM을 조작
            self.driver.find_element_by_id('button_id').click()
            print(f"Clicked the button in {url}")  # 버튼 클릭 메시지를 출력
            #웹 페이지에서 새로운 HTML 요소(=XSS 공격 페이로드의 실행 결과, = 새로운 엘리먼트 )정 가 나타날 때까지 최대 10초 동안 기다리기
            #새로운 엘리먼트는 XSS 페이로드가 실행되었을 때만 생성되는 조건
            WebDriverWait(self.driver, 10).until(EC.presence_of_element_located((By.ID, 'newElement')))
            print(f'Payload triggered a button click in {url}')
            self.save_vulnerability(url, self.ATTACK_TYPE_DOM_BASED_XSS, name)
        except Exception as e:
            print(f"Payload did not trigger a button click as expected: {e}")