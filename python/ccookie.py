import time
import random
import string
import os

class ccookie:

	def __init__(self):
		pass

	def login(user, password):
		pass

	def getKey(self):
		if os.path.isfile('key.asc'):
			pass
		else:
			pass

	def __generateKey(self):
		return ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(32))
