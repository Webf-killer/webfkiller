import mysql.connector

attackDB = mysql.connector.connect(host="localhost",user="root",password="rudtj2306!",database="attackDB")
mycursor = attackDB.cursor()

tables = [ 'payloads_ReflectedXss', 'payloads_StoredXss', 
          'payloads_DOMXss', 'payloads_sqli', 'payloads_OpenRedirection']


for table in tables:
    print(f"Data in {table}:")
    mycursor.execute(f"SELECT * FROM {table} LIMIT 10")
    results = mycursor.fetchall()
    for row in results:
        print(row)
    print("\n")