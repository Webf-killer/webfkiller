import requests
import hashlib
from bs4 import BeautifulSoup
from selenium import webdriver

# URL 수집
# 해야할일 = DB에서 가져오기 (attack.py 참고)
url = 'http://example.com'


#해야할일 = DB정보 가져오기
#해야할일 = 코드 내에서 필요한 DB정보가 무엇인지 정리하기


# 요청 보내고 HTML 정보 받기
response = requests.get(url)
soup = BeautifulSoup(response.text, 'html.parser')

# input 태그 정보 확인 (해야할일 = 필요한 태그는 추가해야함)
for input_tag in soup.find_all('input'):
    name = input_tag.get('name')
    value = input_tag.get('value')

    # Reflected_XSS 취약점 확인(get요청)
    Reflected_xss_payload = '<img src=x onerror=alert(1)>'
    Reflected_xss_payload += hashlib.md5(Reflected_xss_payload.encode()).hexdigest()  # MD5 해시 추가

    # GET 요청을 통한 Reflected XSS 테스트
    Reflected_xss_response_get = requests.get(url, params={name: Reflected_xss_payload})
    if Reflected_xss_payload in Reflected_xss_response_get.text:
        print(f'Possible Reflected XSS in {name} via GET request')
        cursor.execute("INSERT INTO vulnerabilities (url, type, parameter, method) VALUES (%s, %s, %s, %s)", (url, 'Reflected XSS', name, 'GET'))

    # POST 요청을 통한 Reflected XSS 테스트
    Reflected_xss_response_post = requests.post(url, data={name: Reflected_xss_payload})
    if Reflected_xss_payload in Reflected_xss_response_post.text:
        print(f'Possible Reflected XSS in {name} via POST request')
        cursor.execute("INSERT INTO vulnerabilities (url, type, parameter, method) VALUES (%s, %s, %s, %s)", (url, 'Reflected XSS', name, 'POST'))
    
    # Stored_XSS 취약점 확인
    #보낸 input 값이 서버에 저장되는지(Stored)
    # -> 위의 웹사이트 url('http://example.com')
    # 해야할일 : 예시 게시판 글쓰기 URL *이걸 어떻게 구현할지 같이 고민해봐요!*
    # 해야할일 = Stored_xss_payload에 들어갈 내용 찾아서 정리하기 (DVWA 기준으로)
    post_url = 'http://example.com/post'
    Stored_xss_payload = '<img src=x onerror=alert(1)>'
    Stored_xss_payload += hashlib.md5(Stored_xss_payload.encode()).hexdigest()  # MD5 해시 추가
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
            cursor.execute("INSERT INTO vulnerabilities (url, type, parameter, method) VALUES (%s, %s, %s, %s)", (url, 'Stored XSS', name, 'POST'))

    
    # DOM_based_XSS 취약점 확인
    # DOM 조작을 통해 실행되는지(DOM based)
    # -> 위의 웹사이트 url('http://example.com')
    # 해야할일 = DOM_based_xss_payload에 들어갈 내용 찾아서 정리하기 (DVWA 기준으로)
    DOM_based_xss_payload = '<img id="xss" src=x onerror=alert(1)>'

    # 웹 브라우저를 시작 (해야할일 = 어떤 웹 브라우저를 사용하는걸까..?)
    # 또는 webdriver.Chrome()
    driver = webdriver.Firefox()

    # 웹사이트 방문
    driver.get(url)

    # JavaScript를 실행하여 DOM에 악성 스크립트 추가
    driver.execute_script(f'document.body.innerHTML += `{DOM_based_xss_payload}`;')

    # 악성 스크립트가 DOM에 추가되었는지 확인
    if driver.find_element_by_id('xss'):
        print('Possible DOM-based XSS in {url}')
        cursor.execute("INSERT INTO vulnerabilities (url, type, parameter) VALUES (%s, %s, %s)", (url, 'DOM-based XSS', name))
    
    # 웹 브라우저를 종료 시키는게 맞는건지..?
    driver.quit()


    # SQL Injection 공격 요청 패킷 보내기
    sqli_payload = "' OR '1'='1"
    sqli_response = requests.get(url, params={name: sqli_payload})
    
    # 응답에서 SQLi 취약점 확인
    if 'error' in sqli_response.text:
        print(f'Possible SQL Injection in {name}')
        cursor.execute("INSERT INTO vulnerabilities (url, type, parameter) VALUES (%s, %s, %s)", (url, 'SQL Injection', name))

    # Open Redirection 확인
    #-> 위의 웹사이트 url('http://example.com')
    or_payload = 'http://malicious.com'
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
        cursor.execute("INSERT INTO vulnerabilities (url, type, parameter) VALUES (%s, %s, %s)", (url, 'Open Redirection', name))

# DB에 변경 사항 저장
db.commit()

# 웹 브라우저 종료
driver.quit()