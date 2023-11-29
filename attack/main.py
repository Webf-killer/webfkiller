import urllib.parse
import requests
import mysql.connector
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor

import DomXSS, StoredXSS,ReflectedXSS, OR, SQLi

class Attack:
    ATTACK_TYPE_DOM_BASED_XSS = 'Dom_based_xss'
    ATTACK_TYPE_SQLI = 'sqli'
    ATTACK_TYPE_STORED_XSS = 'Stored_XSS'
    ATTACK_TYPE_REFLECTED_XSS = 'Reflected_XSS'
    ATTACK_TYPE_OPEN_REDIRECTION = 'OpenRedirection'

    def __init__(self):
        self.attackDB = self.connect_db()
        self.mycursor = self.attackDB.cursor()
        self.proxies = {'http': 'http://localhost:8080', 'https': 'http://localhost:8080'}
        self.driver = webdriver.Chrome()
        self.urls = self.get_data('urls', 'url')

    def connect_db(self):
        try:
            return mysql.connector.connect(host="localhost", user="root", password="1111", database="attackDB")
        except mysql.connector.Error as err:
            print(f"Failed to connect to database: {err}")
            return None

    def disconnect_db(self):
        if self.attackDB:
            self.attackDB.close()

    def get_data(self, table, column):
        try:
            self.mycursor.execute(f"SELECT {column} FROM {table}")
            results = self.mycursor.fetchall()
            return [row[0] for row in results]
        except mysql.connector.Error as err:
            print(f"Failed to fetch data from database: {err}")
            return []

    def save_vulnerability(self, url, attack_type, param, payload=None):
        if payload:
            self.mycursor.execute("INSERT INTO vulnerabilities (url, type, parameter, payload) VALUES (%s, %s, %s, %s)", (url, attack_type, param, payload))
        else:
            self.mycursor.execute("INSERT INTO vulnerabilities (url, type, parameter) VALUES (%s, %s, %s)", (url, attack_type, param))

    def test_dom_based_xss(self, url):
        DOM_based_xss_payloads = self.get_data('payloads_Domxss', 'payload')
        for DOM_based_xss_payload in DOM_based_xss_payloads:
            manipulated_url_query = f"{url}?name=" + urllib.parse.quote(DOM_based_xss_payload)
            self.driver.get(manipulated_url_query)
            self.check_payload_execution(url, 'name')

    def check_payload_execution(self, url, name):
        try:
            self.driver.find_element_by_id('button_id').click()
            WebDriverWait(self.driver, 10).until(EC.presence_of_element_located((By.ID, 'newElement')))
            print(f'Payload triggered a button click in {url}')
            self.save_vulnerability(url, self.ATTACK_TYPE_DOM_BASED_XSS, name)
        except Exception as e:
            print(f"Payload did not trigger a button click as expected: {e}")

    def test_sqli(self, url):
        sqli_payloads = self.get_data('payloads_sqli', 'payload')
        response = requests.get(url, proxies=self.proxies)
        soup = BeautifulSoup(response.text, 'html.parser')
        for input_tag in soup.find_all('input'):
            name = input_tag.get('name')
            for payload in sqli_payloads:
                manipulated_url = f"{url}?뤼튼=" + payload
                response = requests.get(manipulated_url, proxies=self.proxies)
                if 'error' in response.text:
                    print(f'Possible SQL Injection found in {url} with payload: {payload}')
                    self.save_vulnerability(url, self.ATTACK_TYPE_SQLI, name, payload)

    def test_stored_xss(self, url):
        stored_xss_payloads = self.get_data('payloads_StoredXss', 'payload')
        for payload in stored_xss_payloads:
            self.driver.get(url)
            try:
                inputElement = self.driver.find_element_by_name("input")
                inputElement.send_keys(payload)
                inputElement.submit()
                WebDriverWait(self.driver, 10).until(EC.url_changes(url))
                self.driver.get(url)
                if payload in self.driver.page_source:
                    print(f"Stored XSS payload found in {url}")
                    self.save_vulnerability(url, self.ATTACK_TYPE_STORED_XSS, 'input', payload)
            except Exception as e:
                print(f"Failed to test stored XSS: {e}")

    def test_reflected_xss(self, url):
        reflected_xss_payloads = self.get_data('payloads_ReflectedXss', 'payload')
        for payload in reflected_xss_payloads:
            manipulated_url = f"{url}?name=" + urllib.parse.quote(payload)
            response = requests.get(manipulated_url, proxies=self.proxies)
            if payload in response.text:
                print(f'Reflected XSS payload found in {url} with payload: {payload}')
                self.save_vulnerability(url, self.ATTACK_TYPE_REFLECTED_XSS, 'name', payload)

    def test_open_redirection(self, url):
        open_redirection_payloads = self.get_data('payloads_OpenRedirection', 'payload')
        for payload in open_redirection_payloads:
            manipulated_url = f"{url}?name=" + urllib.parse.quote(payload)
            response = requests.get(manipulated_url, allow_redirects=False, proxies=self.proxies)
            if response.status_code in [301, 302, 303, 307, 308]:
                redirect_url = response.headers.get('Location')
                if redirect_url and redirect_url == payload:
                    print("Open redirection was detected")
                    self.save_vulnerability(url, self.ATTACK_TYPE_OPEN_REDIRECTION, 'name', payload)

    def attack(self):
        self.connect_db()
        with ThreadPoolExecutor(max_workers=5) as executor:
            for url in self.urls:
                executor.submit(self.process_url, url)
        self.driver.quit()
        self.disconnect_db()

if __name__ == "__main__":
    attack = Attack()
    attack.attack()
