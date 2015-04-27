import time
import random
import string
import os
from Crypto.Cipher import AES

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
		pass

	def __decrypt(self, strin):
		pass

	def isValid(self,strin):
		pass

	def getKey(self):
		self.isValid()
		if os.path.isfile('key.asc'):
			f = open('key.asc', 'r')
			self.__key = f.read()
			f.close()
		else:
			f = open('key.asc', 'w')
			self.__key = self.__generateKey()
			f.write(self.__key)
			f.close()

	def __generateKey(self):
		return ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(32))
