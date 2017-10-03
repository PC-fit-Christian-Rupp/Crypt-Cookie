import time
import datetime
from Crypto.Random import random
from Crypto import Random
import string
import os
from Crypto.Cipher import AES
from http import cookies
import cgi
import sys
from random import SystemRandom

class ccookie:

	def __init__(self, updateExpiration = False, timedeltaMinutes = 15, AESKey = None, AESInitialVector = None):
		self.__key = AESKey
		self.__IV = AESInitialVector
		self.__validateKey()
		self.__validateVector()
		self.__updateExpiration = updateExpiration
		self.__timedeltaMinutes = timedeltaMinutes
		self.getKey()
		self.getInitialVector()
		if "HTTP_COOKIE" in os.environ:
			self.__cookie = cookies.SimpleCookie(os.environ["HTTP_COOKIE"])
			self.isValid()
		else:
			self.__newCookie()

	def __newCookie(self):
		self.__cookie = cookies.SimpleCookie()
		self.__cookie["session"]= random.randint(0, 100000000000000000)
		self.__cookie["session"]["domain"] = '.'+ os.environ["SERVER_NAME"]
		self.__cookie["session"]["path"] = '/'
		self.__cookie["session"]["expires"] = self.__expiration().strftime("%a, %d-%b-%Y %H:%M:%S PST")
		self.__cookie[str(self.__toInt(self.__encrypt('IP')))] = self.__toInt(self.__encrypt(os.environ["REMOTE_ADDR"]))

	def __toInt(self, a):
		return int.from_bytes(a, byteorder='big')

	def __toByte(self, a):
		return a.to_bytes((a.bit_length()+7)//8, byteorder='big')

	def __expiration(self):
		if self.__timedeltaMinutes==None:
			return datetime.datetime.now() + datetime.timedelta(days=90)
		return datetime.datetime.now() + datetime.timedelta(minutes=self.__timedeltaMinutes)

	def hasKey(self, a):
		self.__updateExpirationTime()
		if str(self.__toInt(self.__encrypt(a))) in self.__cookie:
			return 1
		else:
			return 0

	def login(self, user, password):
		self.__updateExpirationTime()
		if self.isValid():
			self.__cookie[str(self.__toInt(self.__encrypt('USER')))] = self.__toInt(self.__encrypt(user))
			self.__cookie[str(self.__toInt(self.__encrypt('PASSWORD')))] = self.__toInt(self.__encrypt(password))

	def getUser(self):
		self.__updateExpirationTime()
		if self.isValid():
			try:
				return self.__decrypt(self.__toByte(int(self.__cookie[str(self.__toInt(self.__encrypt('USER')))].value)))
			except (KeyError):
				self.__keyErrorHandler('getUser', self.__encrypt('USER').decode('utf-16'))

	def getPassword(self):
		self.__updateExpirationTime()
		if self.isValid():
			try:
				return self.__decrypt(self.__toByte(int(self.__cookie[str(self.__toInt(self.__encrypt('PASSWORD')))].value)))
			except (KeyError):
				self.__keyErrorHandler('getPassword', self.__encrypt('PASSWORD').decode('utf-16'))

	def __keyErrorHandler(self, function, enckey):
		msg = 'The function '+function+' produces a keyerror with the key '+enckey+'! Please call the website operators with this message!'
		sys.exit(msg)

	def addValue(self, keyword, value):
		self.__updateExpirationTime()
		if self.isValid():
			self.__cookie[str(self.__toInt(self.__encrypt(keyword)))] = self.__toInt(self.__encrypt(value))

	def deleteValue(self, keyword):
		self.__updateExpirationTime()
		if self.isValid():
			try:
				del self.__cookie[str(self.__toInt(self.__encrypt(keyword)))]
			except (KeyError):
				self.__keyErrorHandler('deleteValue', self.__encrypt(keyword).decode('utf-16'))

	def getValue(self, keyword):
		self.__updateExpirationTime()
		if self.isValid():
			try:
				return self.__decrypt(self.__toByte(int(self.__cookie[str(self.__toInt(self.__encrypt(keyword)))].value)))
			except (KeyError):
				self.__keyErrorHandler('getValue', self.__encrypt(keyword).decode('utf-16'))

	def __encrypt(self, strin):
		return AES.new(str.encode(self.__key), AES.MODE_CBC, self.__IV).encrypt(self.__pad(strin))

	def __decrypt(self, strin):
		return self.__unpad((AES.new(str.encode(self.__key), AES.MODE_CBC, self.__IV).decrypt(strin)).decode('utf8'))

	def __pad(self, strin):
		i = 16 - (len(strin)%16)
		for j in range(i):
			strin += '\x0b'
		return strin

	def __unpad(self, strin):
		for i in range(16):
			if strin[-1]=='\x0b':
				strin = strin[:-1]
			else:
				i = 16
		return strin

	def isValid(self):
		self.__updateExpirationTime()
		ip = int(self.__cookie[str(self.__toInt(self.__encrypt('IP')))].value)
		if self.__decrypt(self.__toByte(ip)) == os.environ['REMOTE_ADDR']:
			return 1
		else:
			return 0

	def getKey(self):
		if self.__key != None:
			return self.__key
		if os.path.isfile('key.asc'):
			f = open('key.asc', 'r')
			self.__key = f.read()
			f.close()
		else:
			f = open('key.asc', 'w')
			self.__key = self.__generateKey()
			f.write(self.__key)
			f.close()
		return self.__key

	def getInitialVector(self):
		if self.__IV != None:
			return self.__IV
		if os.path.isfile('initalVector.asc'):
			f = open('initialVector.asc', 'r')
			self.__IV = f.read()
			f.close()
		else:
			f = open('initialVector.asc', 'w')
			self.__IV = self.__generateInitialVector()
			f.write(str(self.__IV))
			f.close()
		return self.__IV

	def __generateInitialVector(self):
		return Random.new().read(AES.block_size)

	def __generateKey(self):
		return ''.join(SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(32))

	def __updateExpirationTime(self):
		if self.__updateExpiration:
			self.__cookie["session"]["expires"] = self.__expiration().strftime("%a, %d-%b-%Y %H:%M:%S PST")

	def __validateKey(self):
		if (self.__key != None) and (len(self.__key) != 32):
			raise Exception("invalid key")

	def __validateVector(self):
		if (self.__IV != None) and (len(self.__IV) != 16):
			raise Exception("invalid vector")
		