import requests
import mysql.connector
from urllib.parse import urlencode

class AttackModule:
    def get_data_for_attack_type(self, table):
        try:
            self.mycursor.execute(f"SELECT data FROM {table}")
            results = self.mycursor.fetchall()
            return [row[0] for row in results]
        except mysql.connector.Error as err:
            print(f"Error: {err}")
            return []

    def __init__(self):
        try:
            self.attackDB = mysql.connector.connect(host="localhost", user="root", password="1111", database="attackDB")
            self.mycursor = self.attackDB.cursor()
        except mysql.connector.Error as err:
            print(f"Error: {err}")
            return

        tables_attack_types = [('payloads_sqli', 'sqli'), ('payloads_xss', 'xss'), ('payloads_or', 'openredir')]
        self.payloads = {attack_type: self.fetch_payloads(table) for table, attack_type in tables_attack_types}

        self.urls = self.fetch_urls()
        self.data = {vuln: self.get_data_for_attack_type(f'{vuln}_data') for vuln in ['sqli', 'xss', 'openredir']}

        methods = ['GET', 'POST', 'PUT']
        for method in methods:
            for vuln in self.data.keys():
                if not self.data[vuln]:
                    continue
                for url in self.urls:
                    for data in self.data[vuln]:
                        for payload in self.payloads[vuln]:
                            self.send_request(method, url, data, payload, vuln)

    def fetch_payloads(self, table):
        try:
            self.mycursor.execute(f"SELECT payload FROM {table}")
            results = self.mycursor.fetchall()
            return [row[0] for row in results]
        except mysql.connector.Error as err:
            print(f"Error: {err}")
            return []

    def fetch_urls(self):
        try:
            self.mycursor.execute("SELECT url FROM urls")
            results = self.mycursor.fetchall()
            return [row[0].strip("'") for row in results]
        except mysql.connector.Error as err:
            print(f"Error: {err}")
            return []

    def send_request(self, method, url, data, payload, vuln):
        if method not in ['GET', 'POST', 'PUT']:
            print(f"Invalid method: {method}")
            return

        try:
            if method == 'GET':
                full_url = f"{url}?{urlencode({data: payload})}"
                print(f"Sending {method} request to: {full_url}")
                response = requests.request(method, full_url)
            else:  # POST or PUT
                data = {data: payload}
                print(f"Sending {method} request to: {url}")
                headers = {'Content-Type': 'application/json'}
                response = requests.request(method, url, json=data, headers=headers)

            self.analyze_response(url, data, payload, response, vuln)
        except requests.exceptions.RequestException as e:
            print(f"{method} request failed: {e}")

    def analyze_response(self, url, data, payload, response, vuln):
        if vuln == 'sqli' and self.is_sqli(response, payload):
            self.log_success(url, data, payload, response.status_code, vuln)
        elif vuln == 'xss' and self.is_xss(response, payload):
            self.log_success(url, data, payload, response.status_code, vuln)
        elif vuln == 'openredir' and self.is_openredir(response, url):
            self.log_success(url, data, payload, response.status_code, vuln)
        else:
            print("Attack failed")

    def is_sqli(self, response, payload):
        return response.status_code == 200 and payload in response.text

    def is_xss(self, response, payload):
        return response.status_code == 200 and payload in response.text

    def is_openredir(self, response, url):
        return response.status_code in [301, 302] and response.headers.get('Location', '') == url

    def log_success(self, url, data, payload, status_code, vuln):
        print("Attack might have been successful")
        self.mycursor.execute(f"CREATE TABLE IF NOT EXISTS success_{vuln} (id INT AUTO_INCREMENT, success LONGTEXT, PRIMARY KEY (id))")
        self.mycursor.execute(f"INSERT INTO success_{vuln} (success) VALUES (%s)",
                            (f"URL: {url}, Data: {data}, Payload: {payload}, Status Code: {status_code}, Vuln: {vuln}",))
        self.attackDB.commit()

attack_module = AttackModule()

