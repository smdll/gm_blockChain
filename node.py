# -*- coding: utf-8 -*-
# 定义区块链节点网页

from flask import *
import sqlite3, json
from time import time, sleep
from lib.gmssl.sm2 import CryptSM2
from lib.gmssl.sm3 import sm3_hash
from uuid import uuid4
from lib.base58 import b58encode, b58decode
import requests, random, threading

"""
https://cloud.tencent.com/developer/article/1100975
Example of a block
block = {
	"index": 1,
	"timestamp": 1506057125.900785,
	"transactions": [
		{
			"sender": "8527147fe1f5426f9dd545de4b27ee00",
			"recipient": "a77f5cdfa2934df3954a5c7c7da5df1f",
			"amount": 5,
			"timestamp": 1506057125.900785,
			"signature": "",
			"pubkey": ""
		},
	],
	"nonce": 324984774000,
	"previous_hash": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
}

Example of a tx
tx = {
	"sender": "8NpQNc8uuPEks1x3JT1H1SV5J6CDZt7UmscWP5TJyCMjmAPWoCARb6heAmx4CqiNfuddWMJpEMBiMkryuaDdzHYbASpnV",
	"recipient": "8NpQNc8uuPEks1x3JT1H1SV5J6CDZt7UmscWP5TJyCMjmAPWoCARb6heAmx4CqiNfuddWMJpEMBiMkryuaDdzHYbASpnV",
	"amount": 5,
	"timestamp": 1506057125.900785,
	"signature": "",
	"pubkey": ""
}
"""

difficulty = 3
address = "EF11JNEdFkPgS5eqS66YvRSC1B1p8h1ozXoYGuDGsdExAGDdVxSEBMrdWnAvMiApK49ERaEJ93gdhEnA6jZLWLmZWQj2j"
port = 8080

class Blockchain(object):
	def __init__(self):
		self.chain = []
		self.current_transactions = []

	def new_block(self):
		if self.chain == []:
			previous_hash = 0
		else:
			previous_hash = self.hash(self.chain[-1])
		random.seed(time())
		block = {"index": len(self.chain) + 1, "timestamp": time(), "transactions": self.current_transactions, "nonce": random.getrandbits(32), "previous_hash": previous_hash}
		self.current_transactions = []
		self.chain.append(block)
		return block

	def add_block(self, block):
		self.chain.append(block)

	def new_transaction(self, value):
		if value["sender"] != "0":
			signature = value.pop("signature", None)
			pubkey = b58decode(value.pop("pubkey", None)).decode("UTF-8")
			msg = json.dumps(value, sort_keys = True).encode("UTF-8")
			status = CryptSM2(public_key = pubkey, private_key = None).verify(signature, msg)
			if not status:
				return False
		self.current_transactions.append(value)
		return True

	@staticmethod
	def hash(block):
		block_string = json.dumps(block, sort_keys = True).encode()
		return sm3_hash(list(block_string))

	@property
	def last_block(self):
		if self.chain == []:
			return []
		return self.chain[-1]

	def valid_pow(self, last_nonce, pow):
		guess = f"{last_nonce}{pow}".encode()
		guess_hash = sm3_hash(list(guess))
		return guess_hash[:difficulty] == "".join(["0" for i in range(difficulty)])

app = Flask(__name__)
blockchain = Blockchain()

@app.route("/checkpow", methods = ["POST"])
def checkpow():
	values = request.get_json()
	required = ["pow", "index", "transactions", "nonce", "previous_hash"]
	if not all(k in values for k in required) or values == None:
		return jsonify({"message": "Missing values"}), 400
	pow = values.pop("pow")
	if not blockchain.valid_pow(last_nonce, pow):
		return jsonify({"message": "POW invalid"}), 400
	last_block = blockchain.last_block
	if last_block == []:
		hash = 0
	else:
		hash = blockchain.hash(last_block)
	if values["previous_hash"] == hash:
		blockchain.add_block(values)
		return jsonify({"message": "sync block ok"}), 200
	else:
		return jsonify({"message": "invalid block"}), 400

@app.route("/newtx", methods = ["POST"])
def new_transaction():
	values = request.get_json()
	# Check that the required fields are in the POST"ed data
	required = ["sender", "recipient", "amount", "signature", "pubkey", "timestamp"]
	if not all(k in values for k in required) or values == None:
		return jsonify({"message": "Missing values"}), 400
	# Create a new Transaction
	if values["sender"] == "0":
		return jsonify({"message": "Transaction invalid"}), 400
	if not blockchain.new_transaction(values):
		return jsonify({"message": "Transaction checksum failed"}), 400
	else:
		return jsonify({"message": f"Transaction will be added to block"}), 200

@app.route("/log", methods = ["POST"])
def get_log():
	values = request.get_json()
	# Check that the required fields are in the POST"ed data
	if not "address" in values or values == None:
		return jsonify({"message": "Missing values"}), 400
	address = values["address"]
	response = {"transactions": []}
	for block in blockchain.chain:
		for tx in block["transactions"]:
			if tx["sender"] == address or tx["recipient"] == address:
				response["transactions"].append(tx)
	return jsonify(response), 200

@app.route("/chain", methods = ["GET"])
def chain():
	return jsonify({"chain": blockchain.chain, "length": len(blockchain.chain),}), 200

@app.route("/ping", methods = ["GET"])
def ping():
	return jsonify({"length": len(blockchain.chain)}), 200

def miner():
	global difficulty
	sleep(5)
	print(">>>广播@%d: 矿工已启动"%time())
	try:
		while True:
			try:
				r = requests.get("http://127.0.0.1:8888/list").json()
				node_list = r["list"]
				difficulty = max(difficulty, r["difficulty"])
			except:
				print(">>>广播@%d: 无法连接节点tracker"%time())
				continue
			last_block = blockchain.last_block
			if last_block == []:
				nonce = 0
			else:
				nonce = last_block["nonce"]
			pow = 0
			while True:
				guess = f"{nonce}{pow}".encode()
				guess_hash = sm3_hash(list(guess))
				if guess_hash[:difficulty] == "".join(["0" for i in range(difficulty)]):
					print(">>>广播@%d: 计算出POW: %d"%(time(), pow))
					break
				pow += 1
			# 检验POW、同步区块
			successful = 0
			# 发送者为 "0" 表明是新挖出的币
			blockchain.new_transaction({"sender": "0", "recipient": address, "amount": 1, "timestamp": time()})
			broadcast = blockchain.new_block()
			broadcast["pow"] = pow
			for url in node_list:
				try:
					r = requests.post("http://%s:%d/checkpow"%(url["addr"], url["port"]), json = broadcast)
				except:
					continue
				if r.status_code == 200:
					successful += 1
				if successful >= len(node_list["list"]):
					break
				continue
			# 半数以上节点通过即可
			if successful >= len(node_list):
				print(">>>广播@%d: %s 获得1个奖励币"%(time(), address[:10]))
			else:
				blockchain.chain.remove(blockchain.last_block)# 删除新生成的区块
				continue
	except KeyboardInterrupt:
		return

if __name__ == "__main__":
	threading.Thread(target = miner).start()
	requests.post("http://127.0.0.1:8888/newnode", json = {"port": port})
	app.run(host = "127.0.0.1", port = port, debug = False)
