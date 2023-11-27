import requests
from bs4 import BeautifulSoup

# 요청을 보낼 URL 리스트
url = 'http://example.com/posts'

# GET 요청을 보내고 응답을 받습니다.
response = requests.get(url)

# 응답의 본문을 HTML로 파싱합니다.
soup = BeautifulSoup(response.text, 'html.parser')

# 모든 태그를 찾습니다.
all_tags = soup.find_all()

# 각 태그와 그 내용을 출력합니다.
for tag in all_tags:
    print(f"Tag: {tag.name}, Content: {tag.text}")

#<div>, <span>, <iframe>, <img>, <object>, <embed>, <body>
#<meta> 페이지 리다이렉션
#

def find_user_input_points(url):
    # GET 요청을 보내고 응답을 받습니다.
    response = requests.get(url)

    # 응답의 본문을 HTML로 파싱합니다.
    soup = BeautifulSoup(response.text, 'html.parser')

    # 사용자의 입력을 받는 태그를 찾습니다. (예: input 태그, textarea 태그)
    input_tags = soup.find_all('input')
    textarea_tags = soup.find_all('textarea')

    # 사용자의 입력을 받는 태그의 이름과 타입을 출력합니다.-> GET INPUT 태그 DB저장 (URL)
    for input_tag in input_tags:
        print(f"Tag: {input_tag.name}, Type: {input_tag.get('type')}")
    for textarea_tag in textarea_tags:
        print(f"Tag: {textarea_tag.name}")

    # POST 요청에서 사용자의 입력을 받는 지점을 찾기 위해 form 태그를 찾습니다.
    form_tags = soup.find_all('form')

    # form 태그의 action 속성값을 출력합니다.-> POST INPUT 태그 저장
    for form_tag in form_tags:
        print(f"Form action: {form_tag.get('action')}")

'''주어진 URL에 GET 요청을 보내고 응답을 받아, 
사용자의 입력을 받는 태그(input 태그와 textarea 태그)를 찾습니다. 
또한 POST 요청에서 사용자의 입력을 받는 지점을 찾기 위해 form 태그를 찾아 
action 속성값을 출력'''