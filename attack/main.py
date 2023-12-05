import mysql.connector
import requests
import urllib.parse
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from urllib.parse import urlparse #OR_도메인 정보 가져올 때 필요
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
import time
import DomXSS, StoredXSS, ReflectedXSS, OR, SQLi
import re
import socket
from importlib import reload
import DomXSS
reload(DomXSS)
from DomXSS import DomXSS
from OR import test_or

class Attack:
    ATTACK_TYPE_DOM_BASED_XSS = 'Dom_based_xss'
    ATTACK_TYPE_SQLI = 'sqli'
    ATTACK_TYPE_STORED_XSS = 'Stored_XSS'
    ATTACK_TYPE_REFLECTED_XSS = 'Reflected_XSS'
    ATTACK_TYPE_OPEN_REDIRECTION = 'OpenRedirection'

    def check_proxy_server(self):
        try:
            host, port = self.proxies['http'].replace('http://', '').split(':')
            sock = socket.create_connection((host, int(port)), timeout=5)
            sock.close()
            return True
        except Exception as e:
            print(f"Failed to connect to proxy server: {e}")
            return False
        
    def check_web_server(self, url):
        try:
            response = requests.get(url, timeout=5)
            return response.status_code == 200
        except Exception as e:
            print(f"Failed to connect to web server: {e}")
            return False
        
    def connect_db(self):
        try:
            return mysql.connector.connect(host="localhost", user="root", password="root", database="attackDB")
        except mysql.connector.Error as err:
            print(f"Failed to connect to database: {err}")
            return None

    def disconnect_db(self):
        if self.attackDB:
            self.attackDB.close()
 

    def __init__(self):
        self.attackDB = self.connect_db()
        self.mycursor = self.attackDB.cursor()
        self.urls = []  # 먼저 빈 리스트로 초기화
        self.proxies = {'http': 'http://localhost:8080', 'https': 'http://localhost:8080'}
        chrome_options = Options()
        chrome_options.add_experimental_option("excludeSwitches", ["enable-logging"])
        self.driver = webdriver.Chrome(options=chrome_options)
        self.driver.get("http://sekurity.online:8080/login.php")  # DVWA 페이지를 바로 연결
        self.payloads = self.get_data('payloads_DOMXss', 'payload')
        self.dom_xss_detector = DomXSS(self.driver, re.compile(r'<script>|</script>|javascript:|onload=|onerror='), self.payloads, self.mycursor, self.attackDB)

        # DVWA 로그인
        WebDriverWait(self.driver, 10).until(EC.presence_of_element_located((By.NAME, "username")))
        WebDriverWait(self.driver, 10).until(EC.presence_of_element_located((By.NAME, "password")))
        WebDriverWait(self.driver, 10).until(EC.presence_of_element_located((By.NAME, "Login")))

        username_input = self.driver.find_element(By.NAME, "username")
        password_input = self.driver.find_element(By.NAME, "password")
        login_button = self.driver.find_element(By.NAME, "Login")

        username_input.send_keys("admin")
        password_input.send_keys("password")
        login_button.click()

        # 페이지를 열어두고, 사용자가 직접 종료할 때까지 기다림
        while len(self.urls) == 0:
            time.sleep(5)
            self.urls = self.get_data('urls', 'url')
            print(f"Current URLs: {self.urls}")  # 현재 urls를 출력
        


    def get_data(self, table, column):
        try:
            self.mycursor.execute(f"SELECT {column} FROM {table}")
            results = self.mycursor.fetchall()
            return [row[0] for row in results]
        except mysql.connector.Error as err:
            print(f"Failed to fetch data from database: {err}")
            return []  
        

    def attack(self):
        self.connect_db()
        with ThreadPoolExecutor(max_workers=5) as executor:
            for url in self.urls:
                if not self.check_web_server(url):
                    print(f"Web server {url} is not available.")
                    continue
                print(f"Processing URL: {url}")  # 처리 중인 url을 출력
                executor.submit(self.process_url, url)
        #self.driver.quit()
        self.disconnect_db()

    def process_url(self, url):
        print(f"Sending GET request to {url} with proxies {self.proxies}")  # GET 요청 보내는 것을 출력
        try:
            response = requests.get(url, timeout=5)
            self.dom_xss_detector.test_dom_based_xss(url)
            print(f"Response status code: {response.status_code}")  # 응답의 상태 코드 출력
        
        except Exception as e:
            print(f"Failed to send GET request: {e}")

        
    def process_or(self, url):
        current_url = attack.driver.current_url #현재 url가져오기 
        domain = urlparse(current_url).netloc #현재 url의 도메인 
        test_or(self, current_url, domain) #url과 도메인 가져가기 
       

if __name__ == "__main__":
    attack = Attack()
    attack.attack()


   