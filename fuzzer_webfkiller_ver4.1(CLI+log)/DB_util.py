# pip install pymysql
import pymysql
from USER_INPUT import mysql_id, mysql_pw, mysql_host, mysql_port


def connect_DB():
    """MySQL 데이터베이스에 로그인하는 함수"""
    try:
        connection = pymysql.connect(
            user=mysql_id,
            password=mysql_pw,  # password
            host=mysql_host,  # mysql
            port=mysql_port,
        )

        # 데이터베이스가 존재하는지 확인하고, 없으면 생성
        with connection.cursor() as cursor:
            cursor.execute("CREATE DATABASE IF NOT EXISTS WebfkillerFuzzer2")
            connection.select_db("WebfkillerFuzzer2")

        # print("DB연결 성공")
        return connection
    except pymysql.MySQLError as e:
        print(f"DB연결 실패: {e}")
        return None


def init_DB(connection):
    """init.sql 파일을 사용하여 데이터베이스를 초기화하는 함수"""
    try:
        cursor = connection.cursor()
        with open("init.sql", "r") as file:
            # SQL 파일의 각 명령을 개별적으로 실행합니다.
            sql_commands = file.read().split(";")
            for command in sql_commands:
                if command.strip():
                    cursor.execute(command)
            connection.commit()
            print("DB초기화 성공")
    except pymysql.MySQLError as e:
        print(f"DB초기화 실패: {e}")


def save_request(connection, method, url, headers, parms):
    """proxy 요청부분 저장"""
    try:
        with connection.cursor() as cursor:
            query = "INSERT INTO ProxyRequest (method, URL, header, Parms) VALUES (%s, %s, %s, %s)"
            cursor.execute(query, (method, url, headers, parms))
        connection.commit()
    except pymysql.MySQLError as e:
        print(f"데이터 저장 실패: {e}")


def save_response(connection, url, status_code, headers, body):
    """proxy 응답부분 저장"""
    try:
        with connection.cursor() as cursor:
            query = "INSERT INTO ProxyResponse (URL, status_code, header, body) VALUES (%s, %s, %s, %s)"
            cursor.execute(query, (url, status_code, headers, body))
        connection.commit()
    except pymysql.MySQLError as e:
        print(f"응답 데이터 저장 실패: {e}")


def is_url_exist(connection, url):
    """URL중복검사"""
    with connection.cursor() as cursor:
        query = "SELECT EXISTS(SELECT 1 FROM ProxyRequest WHERE URL = %s)"
        cursor.execute(query, (url,))
        return cursor.fetchone()[0]


def save_scanner_result(connection, type, url, parms):
    """ScannerResult 테이블에 데이터 저장"""
    try:
        with connection.cursor() as cursor:
            query = "INSERT INTO ScannerResult (type, URL, parms) VALUES (%s, %s, %s)"
            cursor.execute(query, (type, url, parms))
        connection.commit()
    except pymysql.MySQLError as e:
        print(f"스캐너 결과 데이터 저장 실패: {e}")


import pymysql


def save_modified_packet_composer_request(
    connection,
    type,
    status_code,
    time,
    url,
    header,
    randomhash,
    parms,
    parms_count,
    body_size,
    body,
):
    """ModifiedPacketComposerRequest 테이블에 데이터 저장"""
    try:
        with connection.cursor() as cursor:
            query = """
            INSERT INTO ModifiedPacketComposerRequest
            (type, status_code,TIME, URL, header, randomhash, parms, parms_count, body_size, body)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            cursor.execute(
                query,
                (
                    type,
                    status_code,
                    time,
                    url,
                    header,
                    randomhash,
                    parms,
                    parms_count,
                    body_size,
                    body,
                ),
            )
        connection.commit()
    except pymysql.MySQLError as e:
        print(f"111데이터 저장 실패: {e}")


def get_proxy_request(conn, num):
    # num인자를 기준으로 데이터 가져옴
    query = f"SELECT `method`, `URL`, `header`, `Parms` FROM `proxyrequest` WHERE `no`={num}"
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor.fetchone()


def save_selenium_data(connection, url, random_hash, parms, body):
    # 셀레니움 응답데이터 저장
    parms_count = len(parms)
    cursor = connection.cursor()
    query = """
    INSERT INTO ModifiedPacketComposerSelenium (URL, randomhash, parms, parms_count, body)
    VALUES (%s, %s, %s, %s, %s)
    """
    cursor.execute(query, (url, random_hash, str(parms), parms_count, body))
    connection.commit()


def get_modified_request(conn, randomhash):
    # 조작패킷 데이터 조회
    query = f"SELECT `type`, `status_code`,`TIME`, `URL`, `header`, `parms`, `parms_count`, `body_size`, `body` FROM `ModifiedPacketComposerRequest` WHERE `randomhash`='{randomhash}'"
    cursor = conn.cursor()
    cursor.execute(query)
    result = cursor.fetchone()
    # 조회 결과가 없으면 None을 반환하고 함수 종료
    if result is None:
        return None

    # 조회 결과가 있으면 결과 반환
    return result


def get_modified_request_sel(conn, randomhash):
    # ModifiedPacketComposerSelenium 테이블에서 조작된 패킷 조회
    query = f"SELECT `URL`, `randomhash`, `parms`, `parms_count`, `body` FROM `ModifiedPacketComposerSelenium` WHERE `randomhash`='{randomhash}'"
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor.fetchone()


def save_scanner_data(connection, scan_type, url, parms):
    # ScannerResult 테이블에 저장하는 함수.
    cursor = connection.cursor()
    query = """
    INSERT INTO ScannerResult (type, URL, parms)
    VALUES (%s, %s, %s)
    """
    cursor.execute(query, (scan_type, url, str(parms)))
    connection.commit()


def get_ScannerResult(conn):
    query = "SELECT `type`, `URL`, `parms` FROM `ScannerResult`"
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()


def update_body_with_res_raw(connection, random_hash, new_body):
    """랜덤 해시를 사용하여 데이터베이스의 body 필드 업데이트"""
    try:
        with connection.cursor() as cursor:
            query = "UPDATE ModifiedPacketComposerRequest SET body = %s WHERE randomhash = %s"
            cursor.execute(query, (new_body, random_hash))
        connection.commit()
    except pymysql.MySQLError as e:
        print(f"데이터 업데이트 실패: {e}")
