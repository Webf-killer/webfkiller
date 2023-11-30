import requests
import hashlib
from bs4 import BeautifulSoup

def test_sqli(self, url):
    response = requests.get(url, proxies=self.proxies)
    soup = BeautifulSoup(response.text, 'html.parser')
    for input_tag in soup.find_all('input'):
        name = input_tag.get('name')
        for payload in self.payloads:
            hashed_payload = hashlib.md5(payload.encode()).hexdigest()
            manipulated_url = f"{url}?{name}=" + hashed_payload
            response = requests.get(manipulated_url, proxies=self.proxies)
            if 'error' in response.text:
                print(f'Possible SQL Injection found in {url} with payload: {hashed_payload}')
                self.save_vulnerability(url, self.ATTACK_TYPE_SQLI, name, hashed_payload)
