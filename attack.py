import requests 
import mysql.connector
from urllib.parse import urlencode

class AttackModule:
    def __init__(self):
        self.attackDB = mysql.connector.connect(host="localhost",user="root",password="1111",database="attackDB")
        self.mycursor = self.attackDB.cursor()
       
       # 테이블 이름과 공격 유형을 매핑
        tables_attack_types = [('payloads_sqli', 'sqli'), ('payloads_xss', 'xss'), ('payloads_or', 'openredir')]

        # 공격 유형별로 페이로드 가져오기
        self.payloads = {}
        for table, attack_type in tables_attack_types:
            self.mycursor.execute(f"SELECT payload FROM {table}")
            results = self.mycursor.fetchall()
            self.payloads[attack_type] = [row[0] for row in results]

        # URL 가져오기
        self.mycursor.execute("SELECT url FROM urls")
        results = self.mycursor.fetchall()
        self.urls = [row[0] for row in results]  

        # 공격 유형별로 데이터 가져오기
        self.data = {
            'sqli': self.get_data_for_attack_type('sqli_data'),
            'xss': self.get_data_for_attack_type('xss_data'),
            'openredir': self.get_data_for_attack_type('or_data')
        }

        methods = ['GET', 'POST', 'PUT']
        vulns = ['sqli', 'xss', 'openredir']

        for method in methods:
            for vuln in vulns:
                for url in self.urls:
                    for data in self.data[vuln]:
                        for payload in self.payloads[vuln]:
                            self.send_request(method, url, data, payload, vuln)

   
            
    def send_request(self, method, url, data, payload, vuln):
        try:
            if method in ['GET']:
                if vuln == 'sqli':
                    full_url_sqli = f"{url}?{urlencode(data)}={payload}"
                    print(f"Sending {method} request to: {full_url_sqli}")
                    response_sqli = requests.request(method, full_url_sqli)
                    self.analyze_response(url, data, payload, response_sqli, vuln)
                elif vuln == 'xss':
                    full_url_xss = f"{url}?{urlencode(data)}={urlencode(payload)}"
                    print(f"Sending {method} request to: {full_url_xss}")
                    response_xss = requests.request(method, full_url_xss)
                    self.analyze_response(url, data, payload, response_xss, vuln)
                elif vuln == 'openredir':
                    full_url_or = f"{url}?{urlencode(data)}={urlencode(payload)}"
                    print(f"Sending {method} request to: {full_url_or}")
                    response_or = requests.request(method, full_url_or)
                    self.analyze_response(url, data, payload, response_or, vuln)


            elif method in ['POST', 'PUT']:
                if vuln == 'sqli':
                    data_sqli = {data: payload}
                    print(f"Sending {method} request to: {url}")
                    headers = {'Content-Type': 'application/json'}
                    response_sqli = requests.request(method, url, json=data_sqli, headers=headers)
                    self.analyze_response(url, data, payload, response_sqli, vuln)
                elif vuln == 'xss':
                    data_xss = {data: payload}
                    print(f"Sending {method} request to: {url}")
                    headers = {'Content-Type': 'application/json'}
                    response_xss = requests.request(method, url, json=data_xss, headers=headers)
                    self.analyze_response(url, data, payload, response_xss, vuln)
                elif vuln == 'openredir':
                    data_or = {data: payload}
                    print(f"Sending {method} request to: {url}")
                    headers = {'Content-Type': 'application/json'}
                    response_or = requests.request(method, url, json=data_or, headers=headers)
                    self.analyze_response(url, data, payload, response_or, vuln)
               
            else:
                print(f"Invalid method: {method}")
                return
        except requests.exceptions.RequestException as e:
            print(f"{method} request failed: {e}")



    def analyze_response(self, url, data, payload, response, vuln):
        if vuln == 'sqli':
            #응답코드-> 민지
            if response.status_code == 200 and payload in response.text:
                print("Attack might have been successful")
                self.mycursor.execute(f"INSERT INTO success_responses_{vuln} VALUES (%s,%s,%s,%s,%s,%s)",
                            (url, data, payload, response.status_code, vuln))
                self.attackDB.commit()

            # 패턴탐지-> 민지
            # xss_sqli.txt가져오기
            else:
                self.mycursor.execute("SELECT error FROM sqli_errors")
                results = self.mycursor.fetchall()
                self.sqli_errors = [row[0] for row in results] 
                for error in self.sqli_errors:
                    if error in response.text:
                        print(f"Potential SQLi vulnerability detected: {error}")
                        self.mycursor.execute(f"INSERT INTO success_sqli VALUES (%s,%s,%s,%s,%s,%s)",
                                    (url, data, payload, response.text, vuln, error))
                        self.attackDB.commit()
                else:
                    print("Attack failed")        



        elif vuln == 'xss':
            #응답코드-> 민지
            if response.status_code == 200 and payload in response.text:
                print("Attack might have been successful")
                self.mycursor.execute(f"INSERT INTO success_responses_{vuln} VALUES (%s,%s,%s,%s,%s,%s)",
                            (url, data, payload, response.status_code, vuln))
                self.attackDB.commit()
            
            
            # 패턴탐지-> 민지
            # xss_errors.txt가져오기
            else:
                self.mycursor.execute("SELECT error FROM xss_errors")
                results = self.mycursor.fetchall()
                self.xss_errors = [row[0] for row in results] 
                for error in self.xss_errors:
                    if error in response.text:
                        print(f"Potential XSS vulnerability detected: {error}")
                        self.mycursor.execute(f"INSERT INTO success_xss VALUES (%s,%s,%s,%s,%s,%s)",
                                    (url, data, payload, response.text, vuln, error))
                        self.attackDB.commit()
                else:
                    print("Attack failed") 




        elif vuln == 'openredir':
            #응답코드-> 민지
            if response.status_code in [301, 302] and response.headers['Location'] == url:
                print("Attack might have been successful")
                self.mycursor.execute(f"INSERT INTO success_or VALUES (%s,%s,%s,%s,%s,%s)",
                            (url, data, payload, response.status_code, vuln))
                self.attackDB.commit()

            #최종 URL-> 경서 
            elif response.headers['Location'] == response.text:
                print("Attack might have been successful")
                self.mycursor.execute(f"INSERT INTO success_or VALUES (%s,%s,%s,%s,%s,%s)",
                            (url, data, payload, response.status_code, vuln))
                self.attackDB.commit()

            
            # 패턴탐지-> 민지
            # o.r_errors.txt가져오기
            else:
                self.mycursor.execute("SELECT error FROM or_errors")
                results = self.mycursor.fetchall()
                self.or_errors = [row[0] for row in results] 
                for error in self.or_errors:
                    if error in response.text:
                        print(f"Potential OpenRedir vulnerability detected: {error}")
                        self.mycursor.execute(f"INSERT INTO success_or VALUES (%s,%s,%s,%s,%s,%s)",
                                    (url, data, payload, response.text, vuln, error))
                        self.attackDB.commit()
                else:
                    print("Attack failed")

        self.attackDB.commit()


attack_module = AttackModule()
