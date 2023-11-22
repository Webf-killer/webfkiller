#attackweb.py 코드 
#만드는 방법 = 메모장 -> (파일이름)attackweb.py
#메모장 안에 해당 코드 복붙 
#파일 위치 = C:\attackweb
from flask import Flask, request, redirect, render_template_string
import sqlite3
import os

app = Flask(__name__)


memos = []

@app.route('/')
def home():
    return """
    <html>
        <head>
            <title>Mini News</title>
        </head>
        <body>
            <h1>Mini News</h1>
            <ul>
                <li><a href="/news/1">News 1</a></li>
                <li><a href="/xss">XSS</a></li>
                <li><a href="/open_redirect">Open Redirect</a></li>
            </ul>
        </body>
    </html>
    """
@app.route('/news/<int:news_id>')
def news(news_id):
    conn = sqlite3.connect(':memory:')
    conn.execute("CREATE TABLE news (id INT, title TEXT, content TEXT)")
    conn.execute("INSERT INTO news VALUES (1, 'News 1', 'News 1 content')")
    conn.execute("INSERT INTO news VALUES (2, 'News 2', 'News 2 content')")
    conn.execute("INSERT INTO news VALUES (3, 'News 3', 'News 3 content')")
    query = f"SELECT * FROM news WHERE id = '{news_id}'"  # SQL Injection vulnerability
    result = conn.execute(query).fetchall()  
    if result:
        title, content = result[0][1], result[0][2]
    else:
        title, content = 'Not Found', 'Not Found'
    return f'<h1>{title}</h1><p>{content}</p>'

@app.route('/xss', methods=['GET', 'POST'])
def xss():
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
        <form action="/xss" method="POST">
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


@app.route('/open_redirect')
def open_redirect():
    next = request.args.get('next', 'https://www.google.com')  # Open redirection vulnerability
    return redirect(next, code=302)
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)