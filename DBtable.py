import mysql.connector

attackDB = mysql.connector.connect(host="localhost",user="root",password="1111",database="attackDB")
mycursor = attackDB.cursor()

tables = ['attack_types', 'urls', 'xss_data', 'sqli_data', 'or_data', 'payloads_xss', 'payloads_sqli', 'payloads_or']

for table in tables:
    print(f"Data in {table}:")
    mycursor.execute(f"SELECT * FROM {table} LIMIT 10")
    results = mycursor.fetchall()
    for row in results:
        print(row)
    print("\n")
