import requests
import urllib.parse

def test_reflected_xss(self, url):
        reflected_xss_payloads = self.get_data('payloads_ReflectedXss', 'payload')
        for payload in reflected_xss_payloads:
            manipulated_url = f"{url}?name=" + urllib.parse.quote(payload)
            response = requests.get(manipulated_url, proxies=self.proxies)
            if payload in response.text:
                print(f'Reflected XSS payload found in {url} with payload: {payload}')
                self.save_vulnerability(url, self.ATTACK_TYPE_REFLECTED_XSS, 'name', payload)