import mysql.connector

    
def save_vulnerability(self, url, attack_type, parameter, payload=None):
    try:
        self.attackDB.connect()
        if payload:
            insert_query = "INSERT INTO vulnerabilities (url, attack_type, parameter, payload) VALUES (%s, %s, %s, %s)"
            values = (url, attack_type, parameter, payload)
        else:
            insert_query = "INSERT INTO vulnerabilities (url, attack_type, parameter) VALUES (%s, %s, %s)"
            values = (url, attack_type, parameter)
        self.mycursor.execute(insert_query, values)
        self.attackDB.commit()
    except mysql.connector.Error as err:
        print(f"Error: {err}")
    finally:
        self.attackDB.disconnect()
