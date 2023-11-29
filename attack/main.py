import urllib.parse
import requests
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
import mysql.connector
import time
import manage_db, DomXSS, StoredXSS,ReflectedXSS, OR, SQLi

class Attack:
    ATTACK_TYPE_DOM_BASED_XSS = 'Dom_based_xss'
    ATTACK_TYPE_SQLI = 'sqli'
    ATTACK_TYPE_STORED_XSS = 'Stored_XSS'
    ATTACK_TYPE_REFLECTED_XSS = 'Reflected_XSS'
    ATTACK_TYPE_OPEN_REDIRECTION = 'OpenRedirection'

    def connect_db(self):  #패스워드 - 확인 필요 
        try:
            return mysql.connector.connect(host="localhost", user="root", password="root", database="attackDB")
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
        self.proxies = {'http': 'http://localhost:8080', 'https': 'http://localhost:8080'}
        self.driver = webdriver.Chrome()
          
        # 페이지를 열어두고, 사용자가 직접 종료할 때까지 기다림
        while True:
            time.sleep(10)

        self.urls = self.get_data('urls', 'url')
        
        
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
   