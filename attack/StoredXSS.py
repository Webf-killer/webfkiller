from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

def test_stored_xss(self, url):
        stored_xss_payloads = self.get_data('payloads_StoredXss', 'payload')
        for payload in stored_xss_payloads:
            self.driver.get(url)
            try:
                inputElement = self.driver.find_element_by_name("input")
                inputElement.send_keys(payload)
                inputElement.submit()
                WebDriverWait(self.driver, 10).until(EC.url_changes(url))
                self.driver.get(url)
                if payload in self.driver.page_source:
                    print(f"Stored XSS payload found in {url}")
                    self.save_vulnerability(url, self.ATTACK_TYPE_STORED_XSS, 'input', payload)
            except Exception as e:
                print(f"Failed to test stored XSS: {e}")