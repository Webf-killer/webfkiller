#raw데이터 추출


import re
from bs4 import BeautifulSoup

def parse_header(file_path):
    with open(file_path, 'r') as file:
        data = file.read()

    # HTTP 버전, 상태 코드 추출
    http_info_pattern = r'(HTTP/\d\.\d)\s+(\w+)\s+(\S+)'
    http_info_match = re.search(http_info_pattern, data)

    if http_info_match:
        http_version = http_info_match.group(1)
        status_code = http_info_match.group(2)
    else:
        print("Unable to extract HTTP info and status code.")
        return

    # HTML 정보 추출
    soup = BeautifulSoup(data, 'html.parser')

    # href 태그를 통한 URL 주소 추출
    href_pattern = r'href=[\'"]?([^\'" >]+)'
    href_matches = re.findall(href_pattern, data)

    # 스크립트 정보 추출
    scripts = [script['src'] for script in soup.find_all('script') if script.get('src')]

    # 결과 출력
    print(f"HTTP Version: {http_version}")
    print(f"Status Code: {status_code}")
    print("Href URLs:")
    for url in href_matches:
        print(f" - {url}")
    print("Scripts:")
    for script in scripts:
        print(f" - {script}")

# 사용 예시
parse_header('raw_data.txt')

