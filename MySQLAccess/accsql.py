import mysql.connector

config = {'user':'admin',\
        'password':'mutillidae',\
        'database':'elearn'}

cnx = mysql.connector.connect(**config)

print(cnx)

query = "SELECT * FROM Accounts"

mycursor = cnx.cursor()
mycursor.execute(query)

for item in mycursor:
    print(item)


cnx.close()
