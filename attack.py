import requests
import mysql.connector
from urllib.parse import urlencode

# 공격 모듈 클래스 선언
class AttackModule:
    # 초기화 함수
    def __init__(self):
        try:
            # MySQL에 연결 시도
            self.attackDB = mysql.connector.connect(host="localhost", user="root", password="1111", database="attackDB")
            self.mycursor = self.attackDB.cursor()
        except mysql.connector.Error as err:
            # 연결 실패-> 오류 
            print(f"Error: {err}")
            return


        # 데이터를 초기화합니다.
        self.init_data()

    # 데이터 초기화 함수
    
     # 공격 유형에 대한 데이터를 가져오는 함수
    def get_data_for_attack_type(self, table):
        # 테이블 이름에 따라 선택할 열 이름이 달라집니다.
        column = 'payload' if 'payloads' in table else 'url' if table == 'urls' else 'data'
        try:
            # 선택한 열의 데이터를 가져옵니다.
            self.mycursor.execute(f"SELECT {column} FROM {table}")
            results = self.mycursor.fetchall()
            return [row[0] for row in results]
        except mysql.connector.Error as err:
            # 실패하면 오류 메시지를 출력합니다.
            print(f"Error: {err}")
            return []
        
    def init_data(self):
        # 각 공격 유형에 대한 데이터를 가져옵니다.
        self.sql_errors = self.get_data_for_attack_type('sql_errors')
        self.xss_errors = self.get_data_for_attack_type('xss_errors')
        self.or_errors = self.get_data_for_attack_type('or_errors')

        # 각 공격 유형에 대한 페이로드
        tables_attack_types = [('payloads_sqli', 'sqli'), ('payloads_xss', 'xss'), ('payloads_or', 'or')]
        self.payloads = {attack_type: self.get_data_for_attack_type(table) for table, attack_type in tables_attack_types}

        # 공격할 URL들
        self.urls = self.get_data_for_attack_type('urls')
        # 공격에 사용할 데이터
        self.data = {vuln: self.get_data_for_attack_type(f'{vuln}_data') for vuln in ['or', 'xss', 'sqli']}

    # 공격 실행 함수
    def execute_attack(self):
        # 사용할 HTTP 메소드를 정의합니다.
        methods = ['GET', 'POST', 'PUT']
        for method in methods:
            for vuln in self.data.keys():
                if not self.data[vuln]:
                    continue
                for url in self.urls:
                    for data in self.data[vuln]:
                        for payload in self.payloads[vuln]:
                            # 각 공격 유형, URL, 데이터, 페이로드에 대해 요청을 보냅니다.
                            self.send_request(method, url, data, payload, vuln)

    # 요청을 보내는 함수
    def send_request(self, method, url, data_key, payload, vuln):
        if method not in ['GET', 'POST', 'PUT']:
            print(f"Invalid method: {method}")
            return

        try:
            if method == 'GET':
                # GET 요청
                full_url = f"{url}?{urlencode({data_key: payload})}"
                print(f"Sending {method} request to: {full_url}")
                response = requests.request(method, full_url)
            else:  # POST or PUT
                data = {data_key: payload}
                print(f"Sending {method} request to: {url} with data: {data}")
                headers = {'Content-Type': 'application/json'}
                response = requests.request(method, url, json=data, headers=headers)

            # 응답을 분석합니다.
            self.analyze_response(url, data_key, payload, response, vuln)
        except requests.exceptions.RequestException as e:
            print(f"{method} request failed: {e}")

    # 응답 분석 함수
    def analyze_response(self, url, data, payload, response, vuln):
        # 공격 유형에 따라 결과를 분석합니다.
        if vuln == 'sqli' and self.is_sqli(response, payload):
            self.log_success(url, data, payload, response.status_code, vuln)
        elif vuln == 'xss' and self.is_xss(response, payload):
            self.log_success(url, data, payload, response.status_code, vuln)
        elif vuln == 'or' and self.is_or(response, url):
            self.log_success(url, data, payload, response.status_code, vuln)
        else:
            print("Attack failed")

    # SQLi 공격이 성공했는지 확인하는 함수
    def is_sqli(self, response, payload):
        return response.status_code == 200 or any(error in response.text for error in self.sql_errors)

    # XSS 공격이 성공했는지 확인하는 함수
    def is_xss(self, response, payload):
        return response.status_code == 200 or any(error in response.text for error in self.xss_errors)

    # OR 공격이 성공했는지 확인하는 함수
    def is_or(self, response, url):
        return response.status_code in [301, 302] and any(error in response.text for error in self.or_errors)

    # 공격 성공 로그를 남기는 함수
    def log_success(self, url, data_key, payload, status_code, vuln):
        print("Attack might have been successful")
        try:
            # 성공한 공격 정보를 DB에 저장
            self.mycursor.execute(f"CREATE TABLE IF NOT EXISTS success_{vuln} (id INT AUTO_INCREMENT, success LONGTEXT, PRIMARY KEY (id))")
            self.mycursor.execute(f"INSERT INTO success_{vuln} (success) VALUES (%s)", (f"URL: {url}, Data: {data_key}, Payload: {payload}, Status Code: {status_code}, Vuln: {vuln}",))
            self.attackDB.commit()
        except mysql.connector.Error as err:
            print(f"Error: {err}")

# 공격 모듈 객체를 생성하고 공격을 실행합니다.
attack_module = AttackModule()
attack_module.execute_attack()


