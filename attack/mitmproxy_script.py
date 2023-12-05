from mitmproxy import http

WhiteList_url = [  # 필터링 목록 (화이트리스트)
    "http://sekurity.online:8080/",
]
BlackList_url = [  # 필터링 목록 (블랙리스트)
    ".gif",
    ".css",
    ".js",
    ".png",
]


# CLI 출력 파트-----------
def request(flow: http.HTTPFlow) -> None:
    req_url = str(flow.request.url)
    req_method = str(flow.request.method)
    req_headers = str(flow.request.headers)
    req_raw = str(flow.request.text)  # 한글 처리를 위한 인코딩

    if any(domain in req_url for domain in WhiteList_url):  # 화이트리스트로 받기
        if not any(domain2 in req_url for domain2 in BlackList_url):  # 불필요데이터(이미지등)
            print("\\n[Request]")
            print(f"URL: {req_url}")  # URL표시
            print(f"Method: {req_method}")  # 요청메소드
            print(f"Headers: {req_headers}")  # 헤더표시
            print(f"Raw: {req_raw}")  # raw데이터


def response(flow: http.HTTPFlow) -> None:
    res_url = str(flow.request.url)
    res_code = str(flow.response.status_code)
    res_headers = str(flow.response.headers)
    res_raw = str(flow.response.text)  # 한글 처리를 위한 인코딩
    content_type = flow.response.headers.get("content-type", "")

    if any(domain in res_url for domain in WhiteList_url):  # 화이트리스트로 받기
        if not any(domain2 in res_url for domain2 in BlackList_url):  # 불필요데이터(이미지등)
            if not content_type.startswith(
                ("image/", "video/", "audio/")
            ):  # 불필요 정보 필터링
                print("\\n[Response]")
                print(f"URL: {res_url}")  # URL표시
                print(f"Method: {res_code}")  # 상태코드
                print(f"Headers: {res_headers}")  # 헤더표시
                print(f"Raw: {res_raw}")  # raw데이터