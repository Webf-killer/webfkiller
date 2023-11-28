import requests
import hashlib
from bs4 import BeautifulSoup
from selenium import webdriver
import mysql.connector

class Attack:
    ATTACK_TYPE_SQLI = 'sqli'
    ATTACK_TYPE_REFLECTED_XSS = 'Reflected_xss'
    ATTACK_TYPE_STORED_XSS = 'Stored_xss'
    ATTACK_TYPE_DOM_BASED_XSS = 'Dom_based_xss'
    ATTACK_TYPE_OR = 'or'

    METHOD_GET = 'GET'
    METHOD_POST = 'POST'

    def __init__(self):
        self.attackDB = None
        self.mycursor = None
        self.payloads = {}
        self.urls = []
        self.data = {}

    def connect_db(self):
        self.attackDB = mysql.connector.connect(host="localhost", user="root", password="1111", database="attackDB")
        self.mycursor = self.attackDB.cursor()

    def disconnect_db(self):
        if self.attackDB:
            self.attackDB.close()
        self.attackDB = None
        self.mycursor = None

    def get_data(self, table, column):
        self.connect_db()
        try:
            self.mycursor.execute(f"SELECT {column} FROM {table}")
            results = self.mycursor.fetchall()
            return [row[0] for row in results]
        except mysql.connector.Error as err:
            print(f"Error: {err}")
            return []
        finally:
            self.disconnect_db()
        
    def init_data(self):
        self.payloads = {
            self.ATTACK_TYPE_SQLI: self.get_data('payloads_sqli', 'payload'),
            self.ATTACK_TYPE_REFLECTED_XSS: self.get_data('payloads_Reflectedxss', 'payload'),
            self.ATTACK_TYPE_STORED_XSS: self.get_data('payloads_Storedxss', 'payload'),
            self.ATTACK_TYPE_DOM_BASED_XSS: self.get_data('payloads_Domxss', 'payload'),
            self.ATTACK_TYPE_OR: self.get_data('payloads_or', 'payload'),
        }

        # 공격할 URL들
        self.urls = self.get_data('urls', 'url')

        # 공격에 사용할 데이터
        self.data = {
            self.ATTACK_TYPE_OR: self.get_data('or_data', 'data'),
            self.ATTACK_TYPE_REFLECTED_XSS: self.get_data('Reflectedxss_data', 'data'),
            self.ATTACK_TYPE_STORED_XSS: self.get_data('Storedxss_data', 'data'),
            self.ATTACK_TYPE_DOM_BASED_XSS: self.get_data('Domxss_data', 'data'),
            self.ATTACK_TYPE_SQLI: self.get_data('sqli_data', 'data'),
        }


    def test_sqli(self, url, name):
            sqli_payloads = self.get_data('payloads_sqli', 'payload')
            for sqli_payload in sqli_payloads:
                sqli_payload += hashlib.md5(_payload.encode()).hexdigest()
                sqli_response = requests.get(url, params={name: sqli_payload})
        
                # 응답에서 SQLi 취약점 확인
                if 'error' in sqli_response.text:
                    print(f'Possible SQL Injection in {name}')
                    self.mycursor.execute("INSERT INTO vulnerabilities (url, type, parameter) VALUES (%s, %s, %s)", (url, 'SQL Injection', name))

    def test_reflected_xss(self, url, name):
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
    

    def test_stored_xss(self, url, name):
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

    
        def test_dom_based_xss(self, url, name):   
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


            

        # 주어진 URL에 대한 HTTP GET 요청을 보냄. allow_redirects=False로 설정하여 리다이렉트를 허용하지 않음 
        def test_or(url, name):
            response = requests.get(url, allow_redirects=False) #허용해야되는지.. 허용하지 않아야 하는지.. 모르게써염

            # 만약 응답의 상태 코드가 리다이렉트 코드인 경우(301, 302, 303, 307, 308)
            if response.status_code in [301, 302, 303, 307, 308]:
                # 응답 헤더에서 'Location'을 가져와 리다이렉트된 URL을 얻음
                redirect_url = response.headers.get('Location')

                # 만약 리다이렉트된 URL이 존재하고, '/'로 시작하지 않고 주어진 'name'으로 시작하지 않는 경우
                if redirect_url and not redirect_url.startswith('/') and not redirect_url.startswith(name):
                    # Open redirection이 감지된 경우
                    print("Open redirection was detected")
                else:
                    # Open redirection이 아닌 경우
                    print("No open redirection")
            else:
                # 리다이렉트가 없거나 지원되지 않는 상태 코드인 경우
                print("No redirection or unsupported redirection code")

                    #자바스크립트를 통한 이동에 대한 구현 추가해야 함 
     
                    
                
        def attack(self):
            self.connect_db()
            for url in self.urls:
                response = requests.get(url)
                soup = BeautifulSoup(response.text, 'html.parser')

                for input_tag in soup.find_all('input'):
                    name = input_tag.get('name')

                    self.test_sqli(url, name)
                    self.test_reflected_xss(url, name)
                    self.test_stored_xss(url, name)
                    self.test_dom_based_xss(url, name)
                    self.test_or(url, name)

            self.disconnect_db()

if __name__ == "__main__":
    attack = Attack()
    attack.init_data()
    attack.attack()
