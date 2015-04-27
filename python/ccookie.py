import time
from Crypto.Random import random
import string
import os
from Crypto.Cipher import AES
import unicodedata

class ccookie:

	def __init__(self):
		pass

	def login(user, password):
		pass

	def addValue(self, keyword, value):
		pass

	def deleteValue(self, keyword):
		pass

	def getValue(self, keyword):
		pass

	def __encrypt(self, strin):
		return AES.new(str.encode(self.__key), AES.MODE_ECB).encrypt(strin)

	def __decrypt(self, strin):
		return AES.new(str.encode(self.__key), AES.MODE_ECB).decrypt(strin)

	def isValid(self):
		return 1

	def getKey(self):
		if self.isValid():
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

	def getInitalVektor(self):
		pass

	def __generateInitialVektor(self):
		pass

	def __generateKey(self):
		return ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(16))
