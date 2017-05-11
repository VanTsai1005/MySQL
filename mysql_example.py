# coding:utf-8
import MySQLdb
from MySQL_Operate import DBConn

USER=raw_input("UserName : ")
PASS=raw_input("Passwd : ")
HOST="127.0.0.1"
DBNAME="test"
PORT=3306

try:
    db = DBConn(HOST, PORT, USER, PASS, DBNAME)
    db.dbConnect()

    # Query
    state = "SELECT * FROM tableA"
    results = db.exeQuery(state)
    for result in results:
        print str(result[0]) + " , " + result[1]

    #  Insert
    state = "INSERT INTO coding5 (codeA) VALUES ('aaa')"
    db.exeInsert(state)

    # Update
    state = "UPDATE coding5 SET codeA = 'bbb' WHERE codeA = 'aaa'"
    db.exeUpdate(state)

    state = "DELETE coding5 WHERE codeA = 'aaa'"
    db.exeDelete(state)
	
	db.dbClose()
except MySQLdb.Error as e:
    print "Error %d: %s" % (e.args[0], e.args[1])