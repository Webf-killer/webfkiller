# 필요한 모듈들을 임포트합니다.
import urllib.parse
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import requests
import mysql.connector
import re

# DOM 기반 XSS 공격을 테스트하기 위한 클래스를 정의합니다.
class DomXSS:
    # 생성자에서는 웹드라이버, XSS 공격 패턴, 페이로드 리스트, 데이터베이스 커서, 데이터베이스 연결을 인자로 받습니다.
    def __init__(self, driver, dom_xss_pattern, payloads, mycursor, attackDB):
        self.driver = driver  # 웹드라이버 설정
        self.dom_xss_pattern = dom_xss_pattern  # XSS 공격 패턴 설정
        self.payloads = payloads  # 페이로드 리스트 설정
        self.mycursor = mycursor  # 데이터베이스 커서 설정
        self.attackDB = attackDB  # 데이터베이스 연결 설정
        self.ATTACK_TYPE_DOM_BASED_XSS = 'DOM-based XSS'  # 공격 유형을 문자열로 설정

    # 주어진 URL에 대해 DOM 기반 XSS 공격을 테스트하는 메소드입니다.
    def test_dom_based_xss(self, url):
        print("test_dom_based_xss called")  # 메소드 호출 로깅
        try:
            parsed_url = urllib.parse.urlparse(url)  # URL 파싱
            #parameters = urllib.parse.parse_qs(parsed_url.query)  # URL의 쿼리 파라미터 추출
            # if not parameters:  # 쿼리 파라미터가 없으면 메소드 종료
                # print("No parameters found in the URL.")
                # return
            #parameters = list(parameters.keys())[:2]  # 첫 번째와 두 번째 파라미터만 추출
            DOM_based_xss_payloads = self.payloads  # XSS 공격에 사용할 페이로드들을 가져오기
            for DOM_based_xss_payload in DOM_based_xss_payloads:  # 각 페이로드에 대해
                #for parameter in parameters:  # 유력한 파라미터에 대해 XSS 공격 시도
                    manipulated_url_query = f"{url}?default=" + urllib.parse.quote(DOM_based_xss_payload)
                    print(f"Trying with payload: {DOM_based_xss_payload} on parameter: default")
                    self.driver.get(manipulated_url_query)  # XSS 공격 시도
                    self.check_payload_execution(url, DOM_based_xss_payload, 'default')  # XSS 공격이 성공했는지 확인
        except Exception as e:
            print(f"Error in test_dom_based_xss: {e}")  # 에러 메시지 출력

    # XSS 공격이 성공했는지 확인하는 메소드입니다.
    def check_payload_execution(self, url, payload, parameter):
        print("check_payload_execution called")  # 메소드 호출 로깅
        try:
            response_body = self.driver.page_source  # 웹 페이지의 응답 본문을 가져옴
            if self.dom_xss_pattern.search(response_body):  # 응답 본문에서 XSS 공격 패턴을 찾음
                print(f"Possible DOM-based XSS detected in response body of {url}")  # 공격 성공 메시지 출력
        except Exception as e:
            print(f"Error in check_payload_execution: {e}")  # 에러 메시지 출력

    # HTTP 요청에서 XSS 공격 패턴을 찾는 메소드입니다.
    def detect_dom_xss(self, request):
        print("detect_dom_xss called")  # 메소드 호출 로깅
        try:
            method = request["method"]  # HTTP 메소드를 가져옴
            if self.dom_xss_pattern.search(request["url"]):  # URL에서 XSS 패턴을 찾음
                print("Possible DOM-based XSS detected in request URL")  # 공격 성공 메시지 출력
            for header, value in request["headers"].items():  # 각 헤더에 대해
                if self.dom_xss_pattern.search(value):  # 헤더 값에서 XSS 패턴을 찾음
                    print(f"Possible DOM-based XSS detected in request header: {header}")  # 공격 성공 메시지 출력
            if method in ["POST", "PUT", "DELETE"]:
                if self.dom_xss_pattern.search(request["body"]):  # 요청 본문에서 XSS 패턴을 찾음
                    print("Possible DOM-based XSS detected in request body")  # 공격 성공 메시지 출력
            response = requests.get(request["url"], timeout=5)  # 요청 URL로 HTTP 요청을 보냄
            if self.dom_xss_pattern.search(response.text):  # 응답 본문에서 XSS 패턴을 찾음
                print("Possible DOM-based XSS detected in response body")  # 공격 성공 메시지 출력
        except Exception as e:
            print(f"Error in detect_dom_xss: {e}")  # 에러 메시지 출력

    # HTTP 응답에서 XSS 공격 패턴을 찾는 메소드입니다.
    def detect_dom_xss_in_response(self, response):
        print("detect_dom_xss_in_response called")  # 메소드 호출 로깅
        try:
            if self.dom_xss_pattern.search(response.url):  # 응답 URL에서 XSS 패턴을 찾음
                print("Possible DOM-based XSS detected in response URL")  # 공격 성공 메시지 출력
            for header, value in response.headers.items():  # 각 헤더에 대해
                if self.dom_xss_pattern.search(value):  # 헤더 값에서 XSS 패턴을 찾음
                    print(f"Possible DOM-based XSS detected in response header: {header}")  # 공격 성공 메시지 출력
            if self.dom_xss_pattern.search(response.text):  # 응답 본문에서 XSS 패턴을 찾음
                print("Possible DOM-based XSS detected in response body")  # 공격 성공 메시지 출력
        except Exception as e:
            print(f"Error in detect_dom_xss_in_response: {e}")  # 에러 메시지 출력

    # 취약점을 데이터베이스에 저장하는 메소드입니다.
    def save_vulnerability(self, url, attack_type, parameter):
        print("save_vulnerability called")  # 메소드 호출 로깅
        try:
            query = "INSERT INTO vulnerabilities (url, attack_type, parameter) VALUES (%s, %s, %s)"  # 쿼리 작성
            values = (url, attack_type, parameter)  # 쿼리에 바인딩할 값
            self.mycursor.execute(query, values)  # 쿼리 실행
            self.attackDB.commit()  # 데이터베이스에 반영
            print(f"Vulnerability saved: {url} {attack_type} {parameter}")  # 저장 성공 메시지 출력
        except mysql.connector.Error as err:
            print(f"Error in save_vulnerability: {err}")  # 에러 메시지 출력

