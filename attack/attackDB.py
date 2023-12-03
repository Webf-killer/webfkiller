import mysql.connector
# MySQL에 연결
attackDB = mysql.connector.connect(host="localhost",user="root",password="1111",database="attackDB")
mycursor = attackDB.cursor()

# 각 테이블 이름, 열 이름, 데이터 파일 이름을 튜플로 묶어 리스트 생성
tables_files = [('urls', 'url', 'urls_data.txt'),  
                ('payloads_ReflectedXss', 'payload', 'payloads_ReflectedXss.txt'), 
                ('payloads_StoredXss', 'payload', 'payloads_Storedxss.txt'), 
                ('payloads_DOMXss', 'payload', 'payloads_DomXss.txt'), 
                ('payloads_sqli', 'payload', 'payloads_sqli.txt'), 
                ('payloads_OpenRedirection', 'payload', 'payloads_OpenRedirection.txt'), # 수정된 부분
                ('vulnerabilities', 'url, type, parameter, payload', 'vulnerabilities_data.txt')]




# 각 테이블에 대해
for table, column, file in tables_files:
    # 테이블의 기존 데이터 삭제
    mycursor.execute(f"TRUNCATE TABLE {table}")
    attackDB.commit()  # 변경 사항 적용

    # 해당 파일 읽어오기
    with open(file, 'r') as f:
        data = f.read().splitlines()  

   
    # 테이블에 데이터 삽입
    for line in data:
        sql = f"INSERT INTO {table} ({column}) VALUES (%s)"
        mycursor.execute(sql, (line,))

    attackDB.commit()  # 각 테이블에 대해 데이터 삽입이 끝날 때마다 commit 호출 


   




