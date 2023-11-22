import requests
import mysql.connector
from urllib.parse import urlencode

class AttackModule:
    def __init__(self):
        try:
            self.attackDB = mysql.connector.connect(host="localhost", user="root", password="1111", database="attackDB")
            self.mycursor = self.attackDB.cursor()
        except mysql.connector.Error as err:
            print(f"Error: {err}")
            return

        self.init_data()

    def init_data(self):
        self.sql_errors = self.get_data_for_attack_type('sql_errors')
        self.xss_errors = self.get_data_for_attack_type('xss_errors')
        self.or_errors = self.get_data_for_attack_type('or_errors')

        tables_attack_types = [('payloads_sqli', 'sqli'), ('payloads_xss', 'xss'), ('payloads_or', 'or')]
        self.payloads = {attack_type: self.get_data_for_attack_type(table) for table, attack_type in tables_attack_types}

        self.urls = self.get_data_for_attack_type('urls')
        self.data = {vuln: self.get_data_for_attack_type(f'{vuln}_data') for vuln in ['or', 'xss', 'sqli']}

    def get_data_for_attack_type(self, table):
        column = 'payload' if 'payloads' in table else 'url' if table == 'urls' else 'data'
        try:
            self.mycursor.execute(f"SELECT {column} FROM {table}")
            results = self.mycursor.fetchall()
            return [row[0] for row in results]
        except mysql.connector.Error as err:
            print(f"Error: {err}")
            return []

    def execute_attack(self):
        methods = ['GET', 'POST', 'PUT']
        for method in methods:
            for vuln in self.data.keys():
                if not self.data[vuln]:
                    continue
                for url in self.urls:
                    for data in self.data[vuln]:
                        for payload in self.payloads[vuln]:
                            self.send_request(method, url, data, payload, vuln)

    def send_request(self, method, url, data_key, payload, vuln):
        if method not in ['GET', 'POST', 'PUT']:
            print(f"Invalid method: {method}")
            return

        try:
            if method == 'GET':
                full_url = f"{url}?{urlencode({data_key: payload})}"
                print(f"Sending {method} request to: {full_url}")
                response = requests.request(method, full_url)
            else:  # POST or PUT
                data = {data_key: payload}
                print(f"Sending {method} request to: {url} with data: {data}")
                headers = {'Content-Type': 'application/json'}
                response = requests.request(method, url, json=data, headers=headers)

            self.analyze_response(url, data_key, payload, response, vuln)
        except requests.exceptions.RequestException as e:
            print(f"{method} request failed: {e}")

    def analyze_response(self, url, data, payload, response, vuln):
        if vuln == 'sqli' and self.is_sqli(response, payload):
            self.log_success(url, data, payload, response.status_code, vuln)
        elif vuln == 'xss' and self.is_xss(response, payload):
            self.log_success(url, data, payload, response.status_code, vuln)
        elif vuln == 'or' and self.is_or(response, url):
            self.log_success(url, data, payload, response.status_code, vuln)
        else:
            print("Attack failed")

    def is_sqli(self, response, payload):
        return response.status_code == 200 or any(error in response.text for error in self.sql_errors)

    def is_xss(self, response, payload):
        return response.status_code == 200 or any(error in response.text for error in self.xss_errors)

    def is_or(self, response, url):
        return response.status_code in [301, 302] and any(error in response.text for error in self.or_errors)

    def log_success(self, url, data_key, payload, status_code, vuln):
        print("Attack might have been successful")
        try:
            self.mycursor.execute(f"CREATE TABLE IF NOT EXISTS success_{vuln} (id INT AUTO_INCREMENT, success LONGTEXT, PRIMARY KEY (id))")
            self.mycursor.execute(f"INSERT INTO success_{vuln} (success) VALUES (%s)", (f"URL: {url}, Data: {data_key}, Payload: {payload}, Status Code: {status_code}, Vuln: {vuln}",))
            self.attackDB.commit()
        except mysql.connector.Error as err:
            print(f"Error: {err}")

attack_module = AttackModule()
attack_module.execute_attack()

