import requests
from bs4 import BeautifulSoup

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
