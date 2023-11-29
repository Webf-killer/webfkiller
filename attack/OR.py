import requests
import urllib.parse

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