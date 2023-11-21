import requests 
import mysql.connector
import pymysql

class AttackModule:
    def __init__(self):
        attackDB = mysql.connector.connect(host="localhost",user="root",password="1111",database="attackDB")
        mycursor = attackDB.cursor()
       
       # 테이블 이름과 공격 유형을 매핑
        tables_attack_types = [('payloads_sqli', 'sql'), ('payloads_xss', 'xss'), ('payloads_or', 'openredir')]

        # 공격 유형별로 페이로드 가져오기
        self.payloads = {}
        for table, attack_type in tables_attack_types:
            mycursor.execute(f"SELECT payload FROM {table}")
            results = mycursor.fetchall()
            self.payloads[attack_type] = [row[0] for row in results]

        # URL 가져오기
        mycursor.execute("SELECT url FROM urls")
        results = mycursor.fetchall()
        self.urls = [row[0] for row in results]

        # 공격 유형별로 데이터 가져오기
        self.data = {
            'sql': self.get_data_for_attack_type(mycursor, 'sqli_data'),
            'xss': self.get_data_for_attack_type(mycursor, 'xss_data'),
            'openredir': self.get_data_for_attack_type(mycursor, 'or_data')
        }

    def get_data_for_attack_type(self, cursor, table):
        cursor.execute(f"SELECT data FROM {table}")
        results = cursor.fetchall()
        return [row[0] for row in results]
            
    def send_request(self, method, url, data, payload, vuln):
        try:
            if method in ['GET']:
                if vuln == 'sql':
                    full_url_sql = f"{url}{urlencode(data)}{payload}"
                    print(f"Sending {method} request to: {full_url_sql}")
                    response_sql = requests.request(method, full_url_sql)
                    self.analyze_response(url, data, payload, response_sql, vuln)
                elif vuln == 'xss':
                    full_url_xss = f"{url}{urlencode(data)}{urlencode(payload)}"
                    print(f"Sending {method} request to: {full_url_xss}")
                    response_xss = requests.request(method, full_url_xss)
                    self.analyze_response(url, data, payload, response_xss, vuln)
                elif vuln == 'openredir':
                    full_url_or = f"{url}{urlencode(data)}{urlencode(payload)}"
                    print(f"Sending {method} request to: {full_url_or}")
                    response_or = requests.request(method, full_url_or)
                    self.analyze_response(url, data, payload, response_or, vuln)
                else:
                    print("Invalid attack type")
                    return


            elif method in ['POST', 'PUT']:
                if vuln == 'sql':
                    data_sql = {data: payload}
                    print(f"Sending {method} request to: {url}")
                    headers = {'Content-Type': 'application/json'}
                    response_sql = requests.request(method, url, json=data_sql, headers=headers)
                    self.analyze_response(url, data, payload, response_sql, vuln)
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
                    print("Invalid attack type")
                    return
            else:
                print(f"Invalid method: {method}")
                return
        except requests.exceptions.RequestException as e:
            print(f"{method} request failed: {e}")


# full_url_sql , full_url_xss, full_url_o.r 구분해서 패킷을 요청하고 구분해서 응답을 받을 수 있게 하기
# XSS 취약점일 경우 패킷응답을 받고 고유값을 이용해 reflected XSS와 stored XSS를 구분할 수 있어야함
# 그 전에 각 페이로드의 MD5 해시를 사용하여 고유값을 생성


# success_responses 테이블에 기록될 수 있게
# success_xss, success_sqli, success_o.r 이렇게?
# 각 함수별로 성공url,parsed_data,payloads,packet이 안에 들어가도록 


    def analyze_response(self, url, data, payload, response, vuln):
        conn = pymysql.connect(host='localhost', user='root', password='1111', db='attackDB')
        cursor = conn.cursor()

        # Create table if not exists????
        cursor.execute(f'''CREATE TABLE IF NOT EXISTS success_responses_{vuln}
                        (url TEXT, data TEXT, payload TEXT, vuln TEXT, status_code INT, error_message TEXT)''')

        if response.status_code == 200 or response.status_code == 302:
            print("Attack might have been successful")
            cursor.execute(f"INSERT INTO success_responses_{vuln} VALUES (%s,%s,%s,%s,%s,%s)",
                        (url, data, payload, vuln, response.status_code, "Attack might have been successful"))
        else:
            print("Attack failed")

        # Check if any SQL error messages are present in the response
        sql_errors = ['you have an error in your SQL syntax',
                    'Server Error in',
                    'Fatal error',
                    'Microsoft JET Database Engine error',
                    'ORA-00933',
                    'Microsoft OLE DB Provider for ODBC Drivers',
                    'PSQLException',
                    'Unclosed quotation mark after the character string']
        
        #DB에서 가져오면 좋을것 같음!!!! sql_errors.txt, xss_errors.txt, o.r_errors.txt

        if vuln == 'sql':
            for error in sql_errors:
                if error in response.text:
                    print(f"SQL Injection was successful. Error message: {error}")
                    cursor.execute(f"INSERT INTO success_responses_{vuln} VALUES (%s,%s,%s,%s,%s,%s)",
                                (url, data, payload, vuln, response.status_code, error))
        elif vuln == 'xss':
            # Add your XSS success check logic here
            pass
        elif vuln == 'openredir':
            # Add your Open Redirection success check logic here
            pass

        conn.commit()
        conn.close()

# 응답 분석하여 각 취약점 유형에 따른 성공 여부를 따로따로 저장하기
# 분석모듈은 아마 이부분을 구현해야하지 않을까..?
# attack 모듈로 부터 받은 success_xss, success_sqli, success_o.r 
# 성공 여부 확인 코드 



attack_module = AttackModule()
attack_module.send_requests()