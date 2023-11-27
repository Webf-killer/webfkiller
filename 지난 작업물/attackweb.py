#attackweb.py 코드 
#만드는 방법 = 메모장 -> (파일이름)attackweb.py
#메모장 안에 해당 코드 복붙 
#파일 위치 = C:\attackweb
from flask import Flask, request, redirect, render_template_string
from urllib.parse import unquote
import sqlite3
import os

app = Flask(__name__)

# 모든 메모를 저장하는 리스트
memos = []

# 홈 페이지 라우트
@app.route('/')
def home():
    # 간단한 HTML 페이지
    return """
    <html>
        <head>
            <title>AttackServer</title>
        </head>
        <body>
            <h1>AttackServer</h1>
            <ul>
                <li><a href="/XSS/SQLI">XSS/SQLI</a></li>
                <li><a href="/open_redirect">Open Redirect</a></li>
            </ul>
        </body>
    </html>
    """

# XSS/SQLi 공격 테스트 페이지 라우트
@app.route('/XSS/SQLI', methods=['GET', 'POST'])
def xss_sqli():
    # POST 요청인 경우, 사용자의 메모를 리스트에 추가
    if request.method == 'POST':
        memo = request.form.get('memo', '')
        memos.append(memo)
    # GET 요청인 경우, 사용자의 이름을 가져와서 표시
    name = request.args.get('name', '')
    return render_template_string('''
        <h1>Hello, {{ name }}!</h1>
        <form action="/search" method="GET">
            <input type="text" name="n">
            <input type="submit" value="검색">
        </form>
        
        <h2>Memos:</h2>
        <ul>
            {% for memo in memos %}
            <li><a href="/memo?id={{ loop.index }}">{{ memo }}</a></li>
            {% endfor %}
        </ul>
        <form action="/XSS/SQLI" method="POST">
            <input type="text" name="memo">
            <input type="submit" value="메모 추가">
        </form>
    ''', name=name, memos=memos)


# 메모 보는 페이지 라우트
@app.route('/memo')
def memo():
    # 사용자가 요청한 메모의 ID 가져오기
    memo_id = request.args.get('id', '')
    # 유효한 ID인 경우, 해당 메모를 반환
    if memo_id.isdigit() and int(memo_id) <= len(memos):
        memo = memos[int(memo_id) - 1]
        return f"<h1>Memo {memo_id}</h1><p>{memo}</p>"
    # 그렇지 않은 경우, 에러 메시지를 반환
    return "Invalid memo ID"

# 검색 결과 페이지 라우트
@app.route('/search')
def search():
    # 사용자의 검색 쿼리를 가져오기
    query = request.args.get('search', '')
    return render_template_string('''
        <h1>Search Results:</h1>
        <p>Searching for: {{ query }}</p>
        {{ query|safe }}
    ''', query=query)

from urllib.parse import unquote

from flask import redirect, request
from urllib.parse import unquote_plus

# 오픈 리다이렉트 공격 테스트 페이지 라우트
@app.route('/open_redirect')
def open_redirect():
    # 'redirect', 'go', 'return' 파라미터 중 하나를 가져와서 리다이렉트 URL로 사용
    params = ['redirect', 'go', 'return']
    for param in params:
        redirect_url = request.args.get(param)
        if redirect_url:
            redirect_url = unquote_plus(redirect_url)
            return redirect(redirect_url, code=302)
        
    # 리다이렉트할 URL이 제공되지 않은 경우, 에러 메시지를 반환합니다.
    return "No redirect URL provided", 400

# 앱 실행
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)

