#attackweb.py 코드 
#만드는 방법 = 메모장 -> (파일이름)attackweb.py
#메모장 안에 해당 코드 복붙 
#파일 위치 = C:\attackweb
from flask import Flask, request, redirect, render_template_string
from urllib.parse import unquote
import sqlite3
import os

app = Flask(__name__)

memos = []

@app.route('/')
def home():
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

@app.route('/XSS/SQLI', methods=['GET', 'POST'])
def xss_sqli():
    if request.method == 'POST':
        memo = request.form.get('memo', '')
        memos.append(memo)

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

@app.route('/memo')
def memo():
    memo_id = request.args.get('id', '')
    if memo_id.isdigit() and int(memo_id) <= len(memos):
        memo = memos[int(memo_id) - 1]
        return f"<h1>Memo {memo_id}</h1><p>{memo}</p>"
    return "Invalid memo ID"

@app.route('/search')
def search():
    query = request.args.get('search', '')
    return render_template_string('''
        <h1>Search Results:</h1>
        <p>Searching for: {{ query }}</p>
        {{ query|safe }}
    ''', query=query)

from urllib.parse import unquote

from flask import redirect, request
from urllib.parse import unquote_plus

@app.route('/open_redirect')
def open_redirect():
    params = ['redirect', 'go', 'return']
    for param in params:
        redirect_url = request.args.get(param)
        if redirect_url:
            redirect_url = unquote_plus(redirect_url)
            return redirect(redirect_url, code=302)

    return "No redirect URL provided", 400


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)

