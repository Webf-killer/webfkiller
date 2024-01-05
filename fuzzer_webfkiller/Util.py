import DB_util
import json
import os
from urllib.parse import urlencode, urlparse


os_name = os.name
if os_name == "nt":  # 윈도우일경우
    path = "\\"
else:
    path = "/"


def print_result(type, types, url, parms, payload):
    # get요청 url만들기
    # query_string = urlencode(parms)  URL인코딩 필요할경우
    query_string = "&".join([f"{key}={value}" for key, value in parms.items()])
    full_url = url + "?" + query_string

    # 최상위URL추출
    parsed_url = urlparse(url)
    top_level_url = parsed_url.netloc
    safe_top_level_url = top_level_url.replace(":", "_")  # 윈도우에서 콜론X

    # json형식 데이터 양식
    data = {
        "type": types,
        "url": url,
        "parms": parms,
        "payload": payload,
        "use_url": full_url,
    }

    # 파일저장 시작===================
    json_data = json.dumps(data, indent=4)
    file_name = f"Result{path}{safe_top_level_url}.json"
    with open(file_name, "a") as file:
        file.write(json_data + "\n")
    # 파일저장 끝===================

    # 출력 부분=====================
    print(f"WF-log: {types} 취약점 발견!")
    print(f"WF-log: {url}")
    print(f"WF-log: {parms}")
    print(f"WF-log: {payload}")
    print(f"WF-log: ========================================")

    # DB저장
    conn = DB_util.connect_DB()
    DB_util.save_scanner_data(conn, type, url, parms)
