import urllib.parse
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

def test_dom_based_xss(self, url):
        DOM_based_xss_payloads = self.get_data('payloads_Domxss', 'payload')
        for DOM_based_xss_payload in DOM_based_xss_payloads:
            manipulated_url_query = f"{url}?name=" + urllib.parse.quote(DOM_based_xss_payload)
            self.driver.get(manipulated_url_query)
            self.check_payload_execution(url, 'name')


def check_payload_execution(self, url, name):
        try:
            self.driver.find_element_by_id('button_id').click()
            WebDriverWait(self.driver, 10).until(EC.presence_of_element_located((By.ID, 'newElement')))
            print(f'Payload triggered a button click in {url}')
            self.save_vulnerability(url, self.ATTACK_TYPE_DOM_BASED_XSS, name)
        except Exception as e:
            print(f"Payload did not trigger a button click as expected: {e}")