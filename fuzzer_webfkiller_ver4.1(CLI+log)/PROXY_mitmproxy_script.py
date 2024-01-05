from mitmproxy import http
from urllib.parse import urlparse, parse_qs
import DB_util
import subprocess
import re
import os
from concurrent.futures import ThreadPoolExecutor
from USER_INPUT import scan_url

# 데이터베이스 연결 설정
conn = DB_util.connect_DB()
if conn:
    # 데이터베이스 초기화
    DB_util.init_DB(conn)

WhiteList_url = [scan_url]  # 필터링 목록 (화이트리스트)
BlackList_url = [  # 필터링 목록 (블랙리스트)
    ".gif",
    ".css",
    ".js",
    ".png",
]
num = 1


def run_script(command):
    subprocess.Popen(command, shell=False)


# CLI 출력 파트-----------
# 요청파트
def request(flow: http.HTTPFlow) -> None:
    req_url = str(flow.request.url)
    last_segment = req_url.split("/")[-1]
    req_method = str(flow.request.method)
    req_headers = flow.request.headers
    req_raw = flow.request.text
    global num
    os_name = os.name
    if os_name == "nt":  # 윈도우일경우
        py = "python"
        path = "\\"
    else:
        py = "python3"
        path = "/"

    if any(domain in req_url for domain in WhiteList_url):  # 화이트리스트로 받기
        if not last_segment.endswith(tuple(BlackList_url)):  # URL마지막 필터링
            # 헤더를 딕셔너리로 변환
            headers_dict = {k: v for k, v in req_headers.items()}
            # Raw 데이터를 딕셔너리로 변환
            raw_dict = parse_qs(req_raw)
            raw_dict = {k: v[0] for k, v in raw_dict.items()}
            # URL중복검사
            if not DB_util.is_url_exist(conn, req_url):
                # 메소드가 포스트일떄
                if req_raw:
                    # print(f"WF-log: {req_url} 탐지시작")
                    # DB저장
                    DB_util.save_request(
                        conn, req_method, req_url, str(headers_dict), str(raw_dict)
                    )
                    if os_name == "nt":  # 윈도우일경우
                        # 멀티스레드이용
                        with ThreadPoolExecutor(max_workers=4) as executor:
                            script_commands = [
                                f"{py} .{path}Composer_packet_generator.py {num} Stored payload{path}Stored xss payload.txt",
                                f"{py} .{path}Composer_packet_generator.py {num} Reflected payload{path}Reflected xss payload.txt",
                                f"{py} .{path}Composer_packet_generator.py {num} SQLi payload{path}SQL injection payload.txt",
                                f"{py} .{path}Composer_packet_generator_sel2.py {num} payload{path}Dom xss payload.txt",
                            ]
                            for command in script_commands:
                                executor.submit(run_script, command)
                    else:
                        subprocess.Popen(
                            [
                                py,
                                f".{path}Composer_packet_generator.py",
                                str(num),
                                "Stored",
                                f"payload{path}Stored xss payload.txt",
                            ],
                            shell=False,
                        )
                        subprocess.Popen(
                            [
                                py,
                                f".{path}Composer_packet_generator.py",
                                str(num),
                                "Reflected",
                                f"payload{path}Reflected xss payload.txt",
                            ],
                            shell=False,
                        )
                        subprocess.Popen(
                            [
                                py,
                                f".{path}Composer_packet_generator.py",
                                str(num),
                                "SQLi",
                                f"payload{path}SQL injection payload.txt",
                            ],
                            shell=False,
                        )
                        subprocess.Popen(
                            [
                                py,
                                f".{path}Composer_packet_generator_sel2.py",
                                str(num),
                                f"payload{path}Dom xss payload.txt",
                            ],
                            shell=False,
                        )

                    num = num + 1

                # 겟방식일떄
                elif "?" in req_url:
                    # URL에서 쿼리 스트링을 파싱
                    parsed_url = urlparse(req_url)
                    query_params = parse_qs(parsed_url.query)
                    # 쿼리 스트링의 파라미터들을 단일 값으로 변환
                    parm_dict = {k: v[0] for k, v in query_params.items()}
                    # print(f"WF-log: {req_url} 탐지시작")
                    # DB저장
                    DB_util.save_request(
                        conn, req_method, req_url, str(headers_dict), str(parm_dict)
                    )
                    if os_name == "nt":  # 윈도우일경우
                        # 멀티스레드이용
                        with ThreadPoolExecutor(max_workers=4) as executor:
                            script_commands = [
                                f"{py} .{path}Composer_packet_generator.py {num} Stored payload{path}Stored xss payload.txt",
                                f"{py} .{path}Composer_packet_generator.py {num} Reflected payload{path}Reflected xss payload.txt",
                                f"{py} .{path}Composer_packet_generator.py {num} SQLi payload{path}SQL injection payload.txt",
                                f"{py} .{path}Composer_packet_generator_sel2.py {num} payload{path}Dom xss payload.txt",
                            ]
                            for command in script_commands:
                                executor.submit(run_script, command)
                    else:
                        subprocess.Popen(
                            [
                                py,
                                f".{path}Composer_packet_generator.py",
                                str(num),
                                "Stored",
                                f"payload{path}Stored xss payload.txt",
                            ],
                            shell=False,
                        )
                        subprocess.Popen(
                            [
                                py,
                                f".{path}Composer_packet_generator.py",
                                str(num),
                                "Reflected",
                                f"payload{path}Reflected xss payload.txt",
                            ],
                            shell=False,
                        )
                        subprocess.Popen(
                            [
                                py,
                                f".{path}Composer_packet_generator.py",
                                str(num),
                                "SQLi",
                                f"payload{path}SQL injection payload.txt",
                            ],
                            shell=False,
                        )
                        subprocess.Popen(
                            [
                                py,
                                f".{path}Composer_packet_generator_sel2.py",
                                str(num),
                                f"payload{path}Dom xss payload.txt",
                            ],
                            shell=False,
                        )

                    num = num + 1


# 응답파트
def response(flow: http.HTTPFlow) -> None:
    res_code = int(flow.response.status_code)
    res_headers = flow.response.headers
    content_type = flow.response.headers.get("content-type", "")
    try:  # 불필요한 이상한 데이터 들어올때 인코딩 문제 오류처리
        res_url = str(flow.request.url)
        res_raw = str(flow.response.text)
    except Exception as e:
        res_raw = ""
        res_url = ""
    last_segment = res_url.split("/")[-1]
    os_name = os.name
    if os_name == "nt":  # 윈도우일경우
        py = "python"
        path = "\\"
    else:
        py = "python3"
        path = "/"

    if any(domain in res_url for domain in WhiteList_url):  # 화이트리스트로 받기
        if not last_segment.endswith(tuple(BlackList_url)):  # URL마지막 필터링
            if not content_type.startswith(
                ("image/", "video/", "audio/")
            ):  # 불필요 정보 필터링
                # 헤더를 딕셔너리로 변환
                headers_dict = {k: v for k, v in res_headers.items()}

                # Stored 취약점탐지
                if "webfkiller" in res_raw:  # 탐지할 단어입력
                    match = re.search(r"webfkiller_([a-zA-Z0-9]+)_", res_raw)
                    if match:
                        random_hash = match.group(1)
                        DB_util.update_body_with_res_raw(conn, random_hash, res_raw)

                    if os_name == "nt":  # 윈도우일경우
                        subprocess.Popen(
                            f"{py} .{path}Scanner_StoredXSS.py {random_hash}",
                            shell=False,
                        )
                    else:
                        subprocess.Popen(
                            [py, f".{path}Scanner_StoredXSS.py", random_hash],
                            shell=False,
                        )

                    DB_util.save_response(
                        conn, res_url, res_code, str(headers_dict), res_raw
                    )
                else:
                    DB_util.save_response(
                        conn, res_url, res_code, str(headers_dict), res_raw
                    )
