import subprocess
from bs4 import BeautifulSoup
import sys
import DB_util
import ast
import Util

conn = DB_util.connect_DB()

random_hash = sys.argv[1]


request_result = DB_util.get_modified_request(conn, random_hash)

# 결과가 없으면 함수 종료
if request_result is None:
    print("No data found for the given hash.")
    sys.exit()

(
    type,
    status_code,
    time,
    url,
    header,
    parms,
    parms_count,
    body_size,
    body,  # 사용안함
) = request_result

url = url.split("?")[0]
header = ast.literal_eval(header)
parms = ast.literal_eval(parms)
#####################################################################################################
# 여기부터 취약점 탐지 코드


def test_for_syntax_errors_in_script(body):  # composer에서 리턴값(body 값) 받아옴
    soup = BeautifulSoup(body, "html.parser")  # body에서 HTML 추출
    script_tags = soup.find_all("script")  # 텍스트 'script' 추출해서 <script> 부분 추출

    for script in script_tags:
        script_code = script.get_text()  # 스크립트 코드 실행을 위해 get_text()
        if script_code.strip():  # 추출된 코드가 비어있지 않은 경우에만 실행
            try:
                # Node.js를 이용해서 스크립트 실행
                process = subprocess.run(
                    ["node", "-e", script_code],
                    check=True,
                    capture_output=True,
                    text=True,
                )
            except subprocess.CalledProcessError as e:
                # 스크립트 실행 도중 에러 발생 시 -> 에러 결과 + 에러 발생 부분 출력
                print(f"Error detected in script: {script_code}")
                print(e.output)
                return True
    return False


if test_for_syntax_errors_in_script(body):
    payload = next((value for key, value in parms.items() if "webfkiller" in value), "")
    Util.print_result("Stored", "Stored XSS", url, parms, payload)


else:
    print("SyntaxError없음")
