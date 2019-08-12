# -*- coding: utf-8 -*-
# 定义数据库相关操作

import sqlite3
from lib.gmssl.sm3 import sm3_hash

class DB:
	connection = None
	cursor = None
	def __init__(self, db_name):
		self.connection = sqlite3.connect(db_name, check_same_thread = False)
		self.cursor = self.connection.cursor()

	def __del__(self):
		self.connection.close()

	def GetUserData(self, uname):
		hashed_uname = sm3_hash(list(bytes(uname, "UTF-8")))
		result_set = self.cursor.execute("SELECT Data FROM User WHERE HashedName=?", (hashed_uname, ))
		data = result_set.fetchone()
		if data == None:
			return None
		return data[0]

	def NewUser(self, uname, encoded_udata):
		hashed_uname = sm3_hash(list(bytes(uname, "UTF-8")))
		self.cursor.execute("INSERT INTO User(HashedName, Data) VALUES(?, ?)", (hashed_uname, encoded_udata, ))
		self.connection.commit()
