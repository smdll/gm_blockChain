# -*- coding: utf-8 -*-
# 定义钱包网页

from flask import *
import os
from lib.hKeyUtil import *
from lib.hTransaction import *

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
util = KeyUtil(path = "database.db")
tx = Transaction()

@app.route("/login", methods = ["GET", "POST"])
def login():
	if "username" in session:
		return redirect('/')
	if request.method == "POST":
		uname = request.form.get("username")
		hashed_upass = request.form.get("password")
		addr = util.GetUserAddress(uname, hashed_upass)
		if not addr == None:
			session["username"] = uname
			session["address"] = addr
			return redirect('/')
		else:
			return render_template("info.html", title = "登录失败", message = "用户名或密码不正确, ", prevpage = "/login")
	else:
		return send_from_directory("./templates", "login.html")

@app.route("/logout")
def logout():
	if "username" in session:
		session.pop("username")
		session.pop("address")
	return redirect("/login")

@app.route("/register", methods = ["GET", "POST"])
def register():
	if "username" in session:
		session.pop("username")
		session.pop("address")
	if request.method == "POST":
		uname = request.form.get("username")
		hashed_upass = request.form.get("password")
		if util.CheckUserPresent(uname):
			return render_template("info.html", title = "注册失败", message = "用户已存在, ", prevpage = "/register")
		keys = util.NewUser(uname, hashed_upass)
		return render_template("register_ok.html", private_keys = keys)
	return send_from_directory("./templates", "register.html")

@app.route("/xaction", methods = ["POST"])
def transaction():
	if "username" not in session:
		return redirect('/login')
	amount = int(request.form.get("amount"))
	balance, data = tx.GetLog(session["address"])
	if amount > balance:
		return render_template("info.html", title = "交易失败", message = "您的余额不足, ", prevpage = "/")
	recipient = request.form.get("address")
	hashed_upass = request.form.get("password")
	key_share = request.form.get("key")
	private_key, public_key = util.GetUserKeyPair(session["username"], hashed_upass, key_share)
	if private_key != None and tx.Send(private_key, public_key, session["address"], recipient, amount):
		return render_template("info.html", title = "交易成功", message = "交易成功, ", prevpage = "/")
	return render_template("info.html", title = "交易失败", message = "密钥或密码不正确, ", prevpage = "/")

@app.route("/", methods = ["GET"])
def root():
	if "username" not in session:
		return redirect('/login')
	balance, data = tx.GetLog(session["address"])
	return render_template("index.html", result = data, uname = session["username"], address = session["address"], balance = balance)

if __name__ == "__main__":
	app.run(host = "127.0.0.1", port = 80, debug = True)
