import pymysql

connection = pymysql.connect(host='localhost',
                             user='root',
                             password='1111',
                             charset='utf8mb4',
                             )

try:
    with connection.cursor() as cursor:
        cursor.execute("DROP DATABASE mydatabase5;")
        # mydatabase5 생성
        cursor.execute("CREATE DATABASE mydatabase5;")
        # mydatabase5 사용
        cursor.execute("USE mydatabase5;")
        # mytable 테이블 생성
        cursor.execute("""
        CREATE TABLE mytable (
            id INT AUTO_INCREMENT,
            name VARCHAR(100),
            age INT,
            PRIMARY KEY(id)
        );
        """)
        # mytable 테이블에 데이터 입력
        cursor.execute("INSERT INTO mytable (name, age) VALUES ('홍길동', 30);")

    # 변경사항 저장
    connection.commit()

    with connection.cursor() as cursor:
        # mytable 테이블 데이터 조회
        cursor.execute("SELECT * FROM mytable;")
        # 조회 결과 출력
        rows = cursor.fetchall()
        for row in rows:
            print(row)

finally:
    connection.close()