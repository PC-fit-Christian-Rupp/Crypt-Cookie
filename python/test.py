import ccookie
import os
import hashlib
import sys

os.environ['SERVER_NAME']='Test Server Name'
os.environ['REMOTE_ADDR']='255.255.255.255'
print('\nSet enviroment variables!\n')
print('Server name set to "'+ os.environ['SERVER_NAME']+'" for the test routine!')
print('Remote address set to "' +os.environ['REMOTE_ADDR'] +'" for the test routine!\n')
print('Set enviroment variables!\t\tFINISHED')
print('-------------------------------------------------------------------------------')
print('Generate test crypt cookie!\n')
a = ccookie.ccookie()
print('Generate test crypt cookei!\t\tFINISHED')
print('-------------------------------------------------------------------------------')
print('Test session data!\n')
print('Session:\t' + a._ccookie__cookie['session'].value)
print('Domain:\t\t' + a._ccookie__cookie['session']['domain'])
print('Path:\t\t' + a._ccookie__cookie['session']['path'])
print('Expires:\t' + a._ccookie__cookie['session']['expires'])
print('Encrypted IP:\t'+ a._ccookie__cookie[hashlib.sha1(str.encode('IP')).hexdigest()].value+'\n')
print('Test session data!\t\t\tFINISHED')
print('-------------------------------------------------------------------------------')
print('Validation test!\n')
if a.isValid():
	print('Validation test!\t\t\tFINISHED')
else:
	print('Validation test!\t\t\tFAILED')
	sys.exit(0)
