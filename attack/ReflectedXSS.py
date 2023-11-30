import requests
import hashlib
import urllib.parse

def generate_random_string(self, length):
        characters = string.ascii_letters + string.digits
        return ''.join(random.choice(characters) for _ in range(length))

def generate_md5_and_random(self, payload):
    md5_hash = hashlib.md5(payload.encode('utf-8')).hexdigest()
    random_string = self.generate_random_string(8)
    return md5_hash, random_string


def test_reflected_xss(self, url):
        reflected_xss_payloads = self.get_data('payloads_ReflectedXss', 'payload')
        for payload in reflected_xss_payloads:
            manipulated_url = f"{url}?name=" + urllib.parse.quote(payload)
            response = requests.get(manipulated_url, proxies=self.proxies)
            
            # GET 요청
            response = requests.get(manipulated_url, proxies=self.proxies)
            if payload in response.text:
                print(f'Reflected XSS payload found in {url} with payload: {payload}')
                self.save_vulnerability(url, self.ATTACK_TYPE_REFLECTED_XSS, 'name', payload)

            # POST 요청
            response = requests.post(url, data = {'name': payload}, proxies=self.proxies)
            if payload in response.text:
                print(f'Reflected XSS payload found in {url} with payload: {payload}')
                self.save_vulnerability(url, self.ATTACK_TYPE_REFLECTED_XSS, 'name', payload)