from bs4 import BeautifulSoup
import sys
import DB_util
import ast
import Util


conn = DB_util.connect_DB()

random_hash = sys.argv[1]

url, random_hash, parms, parms_count, body = DB_util.get_modified_request_sel(
    conn, random_hash
)

url = url.split("?")[0]
parms = ast.literal_eval(parms)
#####################################################################################################
# 여기부터 취약점 탐지 코드


def test_for_syntax_errors_in_script(body):  # composer에서 리턴값(body 값) 받아옴
    soup = BeautifulSoup(body, "html.parser")  # body에서 HTML 추출

    # 'someattr' 속성이 있는 태그 찾기
    someattr_tag = soup.find(lambda tag: tag.get("someattr") == "1")
    # 'dummy' 속성이 있는데 그 값이 비어있는 태그 찾기
    dummy_tag = soup.find(lambda tag: tag.get("dummy") == "")

    if someattr_tag and dummy_tag:
        payload = next(
            (value for key, value in parms.items() if "webfkiller" in value), ""
        )
        Util.print_result("DOM", "DOM XSS", url, parms, payload)

    else:
        print("")

    return False


test_for_syntax_errors_in_script(body)
