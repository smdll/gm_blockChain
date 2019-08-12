# -*- coding: utf-8 -*-
# 定义交易过程

import requests, json, time
from lib.gmssl.sm2 import CryptSM2
from lib.gmssl.func import random_hex
from lib.base58 import b58encode, b58decode

class Transaction:
	def __init__(self):
		try:
			r = requests.get("http://127.0.0.1:8888/fulllist")
		except:
			print("Tracker服务器无响应")
			return
		addr = r.json()["list"][0]["addr"]
		port = r.json()["list"][0]["port"]
		self.addr = "http://%s:%d"%(addr, port)

	def GetLog(self, address):
		try:
			r = requests.post("%s/log"%self.addr, json = {"address": address}, timeout = 1)
		except:
			return 0, ["节点服务器无响应",]
		response = r.json()
		transactions = response["transactions"]
		log = []
		balance = 0
		for tx in transactions:
			if tx["sender"] == address:
				log.append(f"%s 支出: %d 去往: %s"%(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(tx["timestamp"])), tx["amount"], tx["recipient"][:10]))
				balance -= tx["amount"]
			elif tx["recipient"] == address:
				log.append(f"%s 收入: %d 来自: %s"%(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(tx["timestamp"])), tx["amount"], "奖励货币" if tx["sender"] == '0' else tx["sender"][:10]))
				balance += tx["amount"]
		if log == []:
			return 0, ["无记录",]
		return balance, log

	def Send(self, private_key, public_key, sender, recipient, amount):
		data = {"sender": sender, "recipient": recipient, "amount": amount, "timestamp": time.time()}
		msg = json.dumps(data, sort_keys = True).encode("UTF-8")
		try: crypt_sm2 = CryptSM2(public_key = None, private_key = b58decode(private_key).decode("UTF-8"))
		except: return False
		random_hex_str = random_hex(crypt_sm2.para_len)
		signature = crypt_sm2.sign(msg, random_hex_str)
		data["signature"] = signature
		data["pubkey"] = public_key
		r = requests.post("%s/newtx"%self.addr, json = data)
		if r.status_code == 200:
			return True
		return False