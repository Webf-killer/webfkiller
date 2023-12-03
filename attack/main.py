import mysql.connector
import requests
import urllib.parse
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
import time
import DomXSS, StoredXSS, ReflectedXSS, OR, SQLi

class Attack:
    ATTACK_TYPE_DOM_BASED_XSS = 'Dom_based_xss'
    ATTACK_TYPE_SQLI = 'sqli'
    ATTACK_TYPE_STORED_XSS = 'Stored_XSS'
    ATTACK_TYPE_REFLECTED_XSS = 'Reflected_XSS'
    ATTACK_TYPE_OPEN_REDIRECTION = 'OpenRedirection'

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

    def __init__(self):
        self.attackDB = self.connect_db()
        self.mycursor = self.attackDB.cursor()
        self.urls = []  # 먼저 빈 리스트로 초기화
        self.proxies = {'http': 'http://localhost:8080', 'https': 'http://localhost:8080'}
        chrome_options = Options()
        chrome_options.add_experimental_option("excludeSwitches", ["enable-logging"])
        self.driver = webdriver.Chrome(options=chrome_options)
        self.driver.get("http://sekurity.online:8080/login.php")  # DVWA 페이지를 바로 연결

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
            time.sleep(10)
            self.urls = self.get_data('urls', 'url')
            print(f"Current URLs: {self.urls}")  # 현재 urls를 출력
        
    def attack(self):
        self.connect_db()
        with ThreadPoolExecutor(max_workers=5) as executor:
            for url in self.urls:
                print(f"Processing URL: {url}")  # 처리 중인 url을 출력
                executor.submit(self.process_url, url)
        self.driver.quit()
        self.disconnect_db()

    def process_url(self, url):
        print(f"Sending GET request to {url} with proxies {self.proxies}")  # GET 요청 보내는 것을 출력
        response = requests.get(url, proxies=self.proxies)

if __name__ == "__main__":
    attack = Attack()
    attack.attack()


   