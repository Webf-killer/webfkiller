import mysql.connector

    
def save_vulnerability(self, url, attack_type, param, payload=None): #성공할 때 들어가는 DB
        if payload:
            self.mycursor.execute("INSERT INTO vulnerabilities (url, type, parameter, payload) VALUES (%s, %s, %s, %s)", (url, attack_type, param, payload))
        else:
            self.mycursor.execute("INSERT INTO vulnerabilities (url, type, parameter) VALUES (%s, %s, %s)", (url, attack_type, param))

