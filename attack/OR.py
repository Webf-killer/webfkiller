import requests
import urllib.parse

class OpenRedirectionTest:
    def __init__(self, parent):
        self.parent = parent

    def test_open_redirection(self, url):
        open_redirection_payloads = self.parent.get_data('payloads_OpenRedirection', 'payload')
        
        if not open_redirection_payloads:
            print("No payloads found in 'payloads_OpenRedirection' table")
            return
        
        for payload in open_redirection_payloads:
            manipulated_url = f"{url}?name=" + urllib.parse.quote(payload)
            print(f"Trying with payload: {payload}")
            response = requests.get(manipulated_url, allow_redirects=False, proxies=self.parent.proxies)
            print(f"Response status code: {response.status_code}")
            
            if response.status_code in [301, 302, 303, 307, 308]:
                redirect_url = response.headers.get('Location')
                if redirect_url and redirect_url == payload:
                    print("Open redirection was detected")
                    self.parent.save_vulnerability(url, self.parent.ATTACK_TYPE_OPEN_REDIRECTION, 'name', payload)
                else:
                    print("The payload does not match the redirection URL")
            else:
                print("The status code does not indicate a redirection")
