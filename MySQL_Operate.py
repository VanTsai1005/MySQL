import MySQLdb

class DBConn:
    def __init__(self, host, port, username, passwd, dbname):
        self.host = host
        self.port = port
        self.username = username
        self.passwd = passwd
        self.dbname = dbname

    #   Connect
    def dbConnect(self):
        self.db = MySQLdb.connect(host=self.host, port=self.port, user=self.username, \
                                  passwd=self.passwd, db=self.dbname, charset="utf8")
        self.cursor = self.db.cursor()

    # Close
    def dbClose(self):
      self.db.close()

    # Insert
    def exeInsert(self, statement):
        self.cursor.execute(statement)
        self.db.commit()

    #  Query
    def exeQuery(self, statement):
        self.cursor.execute(statement)
        return self.cursor.fetchall()

    # Update
    def exeUpdate(self, statement):
        self.cursor.execute(statement)
        self.db.commit()

    # Delete
    def exeDelete(self, statement):
        self.cursor.execute(statement)
        self.db.commit()
