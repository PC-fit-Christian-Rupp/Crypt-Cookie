import ccookie
import os

class init:

	def __init__(self):
		os.environ['SERVER_NAME']='test'
		os.environ['REMOTE_ADDR']='255.255.255.255'
		self.cookie = ccookie.ccookie()

	def getCookie(self):
		return self.cookie

if __name__ == '__main__':
	a = init()
