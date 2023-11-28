from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By
from selenium import webdriver
from bs4 import BeautifulSoup
import mysql.connector
from concurrent.futures import ThreadPoolExecutor
import urllib.parse
import requests

# 공격 클래스 정의
class Attack:
    ATTACK_TYPE_DOM_BASED_XSS = 'Dom_based_xss'

    # 초기화 함수
    def __init__(self):
        # 데이터베이스 연결 초기화
        self.attackDB = self.connect_db()
        self.mycursor = self.attackDB.cursor()
        # 페이로드, URL, 데이터를 데이터베이스에서 가져옴
        self.payloads = self.get_data('payloads_Domxss', 'payload')
        self.urls = self.get_data('urls', 'url')
        self.data = self.get_data('Domxss_data', 'data')
        # 프록시 설정
        self.proxies = 'http://localhost:8080'
        # 웹 드라이버 설정
        self.driver = webdriver.Chrome()

    # 데이터베이스 연결 함수
    def connect_db(self):
        try:
            return mysql.connector.connect(host="localhost", user="root", password="1111", database="attackDB")
        except mysql.connector.Error as err:
            print(f"Failed to connect to database: {err}")
            return None

    # 데이터베이스 연결 해제 함수
    def disconnect_db(self):
        if self.attackDB:
            self.attackDB.close()

    # 데이터베이스에서 데이터 가져오는 함수
    def get_data(self, table, column):
        if not self.attackDB:
            print("Database connection is not established.")
            return []
        try:
            self.mycursor.execute(f"SELECT {column} FROM {table}")
            results = self.mycursor.fetchall()
            return [row[0] for row in results]
        except mysql.connector.Error as err:
            print(f"Failed to fetch data from database: {err}")
            return []

    # DOM-based XSS 테스트 함수
    def test_dom_based_xss(self, url, name):   
        # 데이터베이스에서 페이로드를 가져옴
        DOM_based_xss_payloads = self.get_data('DOM_based_xss_payload', 'payload')
        for DOM_based_xss_payload in DOM_based_xss_payloads:
            # 페이로드를 쿼리 문자열에 추가하여 웹 페이지에 전달
            manipulated_url_query = url + "?param=" + urllib.parse.quote(DOM_based_xss_payload)
            self.driver.get(manipulated_url_query)
            # 페이로드 실행 체크
            self.check_payload_execution(url, name)

            # 페이로드를 URL 경로에 추가하여 웹 페이지에 전달
            manipulated_url_path = url + DOM_based_xss_payload
            self.driver.get(manipulated_url_path)
            # 페이로드 실행 체크
            self.check_payload_execution(url, name)

    # 페이로드 실행 체크 함수
    def check_payload_execution(self, url, name):
        # 페이로드가 버튼 클릭을 트리거하도록 설정되었는지 확인
        try:
            self.driver.find_element_by_id('button_id').click()
            WebDriverWait(self.driver, 10).until(EC.presence_of_element_located((By.ID, 'newElement')))
            print(f'Payload triggered a button click in {url}')
            # 공격 성공 정보를 데이터베이스에 저장
            self.mycursor.execute("INSERT INTO vulnerabilities (url, type, parameter) VALUES (%s, %s, %s)", (url, 'DOM-based XSS', name))
        except Exception as e:
            print(f"Payload did not trigger a button click as expected: {e}")

        # 페이로드가 폼 제출을 트리거하도록 설정되었는지 확인
        try:
            self.driver.find_element_by_id('form_id').submit()
            WebDriverWait(self.driver, 10).until(EC.url_changes(url))
            print(f'Payload triggered a form submission in {url}')
            # 공격 성공 정보를 데이터베이스에 저장
            self.mycursor.execute("INSERT INTO vulnerabilities (url, type, parameter) VALUES (%s, %s, %s)", (url, 'DOM-based XSS', name))
        except Exception as e:
            print(f"Payload did not trigger a form submission as expected: {e}")

    # 공격 시작 함수
    def attack(self):
        # 여러 URL을 동시에 처리하기 위해 ThreadPoolExecutor 사용
        with ThreadPoolExecutor(max_workers=5) as executor:
            for url in self.urls:
                executor.submit(self.process_url, url)
        # 웹 드라이버 종료하고 데이터베이스 연결 해제
        self.disconnect_db()

    # URL을 처리하는 함수
    def process_url(self, url):
        # HTTP GET 요청을 통해 URL의 HTML 내용을 가져옴
        response = requests.get(url)
        # BeautifulSoup 라이브러리를 이용하여 HTML을 파싱하고 모든 <input> 태그를 찾음
        soup = BeautifulSoup(response.text, 'lxml')
        for input_tag in soup.find_all('input'):
            name = input_tag.get('name')
            self.test_dom_based_xss(url, name)

if __name__ == "__main__":
    # Attack 객체를 생성하고 공격 시작
    attack = Attack()
    attack.attack()


