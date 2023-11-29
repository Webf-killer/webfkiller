import mysql.connector

def connect_db(self):  #패스워드 - 확인 필요 
        try:
            return mysql.connector.connect(host="localhost", user="root", password="1111", database="attackDB")
        except mysql.connector.Error as err:
            print(f"Failed to connect to database: {err}")
            return None

def disconnect_db(self):
    if self.attackDB:
        self.attackDB.close()

def get_data(self, table, column):
    try:
        self.mycursor.execute(f"SELECT {column} FROM {table}")
        results = self.mycursor.fetchall()
        return [row[0] for row in results]
    except mysql.connector.Error as err:
        print(f"Failed to fetch data from database: {err}")
        return []
    
def save_vulnerability(self, url, attack_type, param, payload=None): #성공할 때 들어가는 DB
        if payload:
            self.mycursor.execute("INSERT INTO vulnerabilities (url, type, parameter, payload) VALUES (%s, %s, %s, %s)", (url, attack_type, param, payload))
        else:
            self.mycursor.execute("INSERT INTO vulnerabilities (url, type, parameter) VALUES (%s, %s, %s)", (url, attack_type, param))

