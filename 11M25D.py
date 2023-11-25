#공격 대상 URL DB 변경
#각 취약점별 공격에 사용될 페이로드 변경
# reflected_payload, dom_payload, sql_payload, Stored xss payload, OpenRedriection payload
# 입력 필드 이름?
#-> 
# 파싱할 HTML 태그 및 속성
# -> BeautifulSoup를 사용하여 HTML을 파싱할 때, 
# soup.find() 함수의 인자로 전달되는 태그 이름과 속성은 실제 웹페이지의 구조에 맞게 변경해야 합니다.

import requests
import hashlib
import mysql.connector
from bs4 import BeautifulSoup

class AttackModule:

    def generate_hash(payload):
        m = hashlib.sha256()
        m.update(payload.encode('utf-8'))
        return m.hexdigest()


    def insert_to_db(signature, payload, xss_type):
        try:
            conn = mysql.connector.connect(user='your_username', password='your_password', host='localhost', database='your_database')
            cursor = conn.cursor()
            sql = "INSERT INTO xss_payloads (signature, payload, xss_type) VALUES (%s, %s, %s)"
            val = (signature, payload, xss_type)
            cursor.execute(sql, val)
            conn.commit()
            print(cursor.rowcount, "record inserted.")
        except mysql.connector.Error as err:
            print("Something went wrong: {}".format(err))
        finally:
            if conn:
                cursor.close()
                conn.close()


    def get_data(self, table, column, condition_column=None, condition_value=None):
        if condition_column and condition_value:
            self.cursor.execute(f"SELECT {column} FROM {table} WHERE {condition_column} = %s", (condition_value,))
        else:
            self.cursor.execute(f"SELECT {column} FROM {table}")
        results = self.cursor.fetchall()
        return [result[0] for result in results]
    
        # 데이터를 초기화합니다.
        #(페이로드, url 리스트, 각 url에 해당하는 입력필드)
        self.init_data()
    
    def init_data(self):
        # 공격 페이로드를 가져옵니다.
        self.payloads = {
            "sqli": self.get_data('payloads_sqli', 'payload'),
            "xss": self.get_data('payloads_xss', 'payload'),
            "or": self.get_data('payloads_or', 'payload'),
        }

        # URL 리스트를 가져옵니다.
        self.urls = self.get_data("urls", "url")

        # 각 URL에 해당하는 입력 필드를 가져옵니다.
        self.input_fields = {url: self.get_data("input_fields", "field_name", "url", url) for url in self.urls}

    #각 URL과 입력 필드에 대해 공격
    #공격 페이로드를 입력 필드에 삽입하여 POST 요청
    def perform_attack(self):
        for url in self.urls:
            input_fields = self.input_fields[url]
            for input_field in input_fields:
                for attack_type, payloads in self.payloads.items():
                    for payload in payloads:
                        if "GET" in attack_type:
                            response = requests.get(url, params={input_field: payload})
                        elif "POST" in attack_type:
                            response = requests.post(url, data={input_field: payload})

                        soup = BeautifulSoup(response.text, 'html.parser')
                        used_payload = soup.find(input_field, {'name': 'user_input'}).get('value')

                        if used_payload in payloads:
                            print(f"공격 성공: {url}, {input_field}, {payload}")
                            payload_hash = self.generate_hash(payload)
                            self.insert_to_db(payload_hash, used_payload, attack_type)

    def perform_redirection_attack(redirect_url):
        url = 'http://example.com/redirect'

        for request_type in ["GET", "POST"]:
            if request_type == "GET":
                response = requests.get(url, params={'redirect': redirect_url})
            elif request_type == "POST":
                response = requests.post(url, data={'redirect': redirect_url})

            if response.status_code == 302 and response.headers['Location'] == redirect_url:
                print("{} 요청으로 Open Redirection 취약점이 탐지되었습니다. 페이로드: ".format(request_type) + redirect_url)


    def close(self):
        self.cursor.close()
        self.conn.close()

attack_module = AttackModule()
attack_module.perform_attack()
attack_module.close()
