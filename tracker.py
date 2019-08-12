from flask import *
import json, time, requests, threading, math

app = Flask(__name__)
'''
node_list = [
	{"addr": "127.0.0.1", "port": 8080}
]
'''
node_list = []
difficulty = 1

# 删除下线的节点
def check_node():
	global difficulty
	max_length = 0
	while True:
		for node in node_list:
			try:
				r = requests.get("http://%s:%d/ping"%(node["addr"], node["port"]))
				max_length = max(max_length, r.json()["length"])
			except KeyboardInterrupt:
				return
			except:
				print(">>>广播@%d: %s:%d 已下线"%(time.time(), node["addr"], node["port"]))
				node_list.pop(node_list.index(node))
		new_difficulty = int(math.floor(math.log(max_length + 1) / math.log(10))) + 1
		if new_difficulty > difficulty:
			difficulty = new_difficulty
			print(">>>广播@%d: 挖矿复杂度增加至%d"%(time.time(), difficulty))
		time.sleep(10)

def check_exists(addr):
	for node in node_list:
		if node["addr"] == addr:
			return True
	return False

def exclude_exists(addr):
	new_list = []
	for node in node_list:
		# 删除重复的节点
		if node["addr"] != addr:
			new_list.append(node)
			break
	return new_list

@app.route("/list", methods = ["GET"])
def list():
	global difficulty
	new_list = exclude_exists(request.remote_addr)
	return jsonify({"list": new_list, "difficulty": difficulty}), 200

@app.route("/fulllist", methods = ["GET"])
def fulllist():
	return jsonify({"list": node_list}), 200

@app.route("/newnode", methods = ["POST"])
def newnode():
	values = request.get_json()
	if "port" not in values or values == None:
		return jsonify({"message": "missing values"}), 400
	if check_exists(request.remote_addr):
		return jsonify({"message": "already joined"}), 400
	node_list.append({
		"addr": request.remote_addr,
		"port": values["port"]
	})
	print(">>>广播@%d: %s:%d 加入节点列表"%(time.time(), request.remote_addr, values["port"]))
	return jsonify({"message": "new node joined"}), 200

if __name__ == "__main__":
	threading.Thread(target = check_node).start()
	app.run(host = "127.0.0.1", port = 8888, debug = False)