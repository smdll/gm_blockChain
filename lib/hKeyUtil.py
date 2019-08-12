# -*- coding: utf-8 -*-
# 定义密钥功能

from lib.gmssl.sm3 import sm3_hash
from lib.gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT
from lib.gmssl.utils import PrivateKey
from lib.secretsharing import BitcoinToB58SecretSharer
from lib.base58 import b58encode, b58decode
from ast import literal_eval
from lib.hDBAccess import DB
import json

class KeyUtil:
	def __init__(self, path):
		self.db = DB(path)

	def __sm3Hash(self, inputStr):
		return sm3_hash(list(bytes(inputStr, "UTF-8")))

	def CheckUserPresent(self, uname):
		encoded_cipher = self.db.GetUserData(uname)
		if not encoded_cipher == None:
			return True
		return False

	def NewUser(self, uname, hashed_upass):
		priKey = PrivateKey()
		pubKey = priKey.publicKey().toString(compressed = False)
		hash = self.__sm3Hash(self.__sm3Hash(pubKey))[:128]
		check = self.__sm3Hash(self.__sm3Hash(hash))[:4]
		userAddr = b58encode(hash + check).decode("UTF-8")
		keyShares = BitcoinToB58SecretSharer.split_secret(b58encode(priKey.toString()).decode("UTF-8"), 2, 3)
		iv = bytes.fromhex(self.__sm3Hash(uname))[0:128]
		key = bytes.fromhex(hashed_upass)[0:128]
		crypt_sm4 = CryptSM4()
		crypt_sm4.set_key(key, SM4_ENCRYPT)
		plain = {"uname":uname, "addr":userAddr, "key":keyShares[0], "pubKey":b58encode(pubKey).decode("UTF-8")}
		cipher = crypt_sm4.crypt_cbc(iv, json.dumps(plain, sort_keys = True).encode("UTF-8"))
		encoded_cipher = b58encode(cipher).decode("UTF-8")
		self.db.NewUser(uname, encoded_cipher)
		return {"first": keyShares[1], "second": keyShares[2]}

	def GetUserAddress(self, uname, hashed_upass):
		encoded_cipher = self.db.GetUserData(uname)
		if encoded_cipher == None:
			return None
		hashed_uname = self.__sm3Hash(uname)
		iv = bytes.fromhex(hashed_uname)[:128]
		key = bytes.fromhex(hashed_upass)[:128]
		cipher = b58decode(encoded_cipher)
		crypt_sm4 = CryptSM4()
		crypt_sm4.set_key(key, SM4_DECRYPT)
		try:
			plain = crypt_sm4.crypt_cbc(iv, cipher).decode("UTF-8")
			udata = json.loads(plain)
			if not udata == None and udata["uname"] == uname:
				return udata["addr"]
		except:
			pass
		return None

	def GetUserKeyPair(self, uname, hashed_upass, prikey_share):
		encoded_cipher = self.db.GetUserData(uname)
		if encoded_cipher == None:
			return None, None
		hashed_uname = self.__sm3Hash(uname)
		iv = bytes.fromhex(hashed_uname)[:128]
		key = bytes.fromhex(hashed_upass)[:128]
		cipher = b58decode(encoded_cipher)
		crypt_sm4 = CryptSM4()
		crypt_sm4.set_key(key, SM4_DECRYPT)
		try:
			plain = crypt_sm4.crypt_cbc(iv, cipher).decode("UTF-8")
			shares = [prikey_share]
			udata = json.loads(plain)
			if not udata == None:
				shares.append(udata["key"])
				prikey = BitcoinToB58SecretSharer.recover_secret(shares)
				return prikey, udata["pubKey"]
		except:
			pass
		return None, None
