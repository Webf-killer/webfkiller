#HTTP POST 요청 패킷 예시
#DB에 url, header정보, data들이 다음과 같은 형식으로 저장되어야함
#이걸 공격모듈에 어떻게 넣을까

import requests

url = 'http://www.example.com/login'
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate, br',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Connection': 'Keep-Alive',
    'Upgrade-Insecure-Requests': '1',
    'Cookie': 'sessionid=abcd1234; username=guest',
}
data = {
    'username': 'testuser',
    'password': '1234'
}

response = requests.post(url, headers=headers, data=data)
