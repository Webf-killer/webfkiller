import mysql.connector

attackDB = mysql.connector.connect(host="localhost",user="root",password="1111",database="attackDB")
mycursor = attackDB.cursor()

tables_files = [('urls', 'url', 'urls_data.txt'), ('xss_data', 'data', 'xss_data.txt'), ('sqli_data', 'data', 'sqli_data.txt'), 
                ('or_data', 'data', 'o.r_data.txt'), ('payloads_xss', 'payload', 'payloads_xss.txt'), 
                ('payloads_sqli', 'payload', 'payloads_sqli.txt'), ('payloads_or', 'payload', 'payloads_o.r.txt'),
                ('sql_errors','error', 'sql_errors.txt'),('xss_errors','error', 'xss_errors.txt'),('or_errors','error', 'o.r_errors.txt')]

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


   




