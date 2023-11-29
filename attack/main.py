import urllib.parse
import requests
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor

import manage_db, DomXSS, StoredXSS,ReflectedXSS, OR, SQLi

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
