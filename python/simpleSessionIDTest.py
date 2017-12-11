import ccookie
import os
import hashlib
import sys
from time import sleep
import datetime
from Crypto.Cipher import AES
from Crypto.Random import random
from Crypto import Random
from random import SystemRandom
import string

os.environ['SERVER_NAME']='Test Server Name'
os.environ['REMOTE_ADDR']='255.255.255.255'
print('--------------------------------------------------------------------------------')
print('Test with Simple Session ID\n')
print('Set enviroment variables!\n')
print('Server name set to "'+ os.environ['SERVER_NAME']+'" for the test routine!')
print('Remote address set to "' +os.environ['REMOTE_ADDR'] +'" for the test routine!\n')
print('Set enviroment variables!\t\t\t\t\t\tFINISHED')
print('-------------------------------------------------------------------------------')
print('Generate test crypt cookie!\n')
oCookie = ccookie.ccookie()
print('Generate test crypt cookei!\t\t\t\t\t\tFINISHED')
print('--------------------------------------------------------------------------------')
print('Test session data!\n')
print('Session:\t' + oCookie.getSessionID())
print('Domain:\t\t' + oCookie._ccookie__cookie['session']['domain'])
print('Path:\t\t' + oCookie._ccookie__cookie['session']['path'])
print('Expires:\t' + oCookie._ccookie__cookie['session']['expires'])
print('Encrypted IP:\t'+ oCookie._ccookie__cookie[str(oCookie._ccookie__toInt(oCookie._ccookie__encrypt('IP')))].value+'\n')
print('Test session data!\t\t\t\t\t\t\tFINISHED')
print('--------------------------------------------------------------------------------')
print('Validation test!\n')
if oCookie.isValid():
	print('Validation test!\t\t\t\t\t\t\tFINISHED')
else:
	print('Validation test!\t\t\t\t\t\t\tFAILED')
	sys.exit(0)
print('--------------------------------------------------------------------------------')
usr='Mad Max'
pwd='Donnerkupel'
print('Login data test!\n')
print('Testdata:')
print('\tUser name:\t'+usr)
print('\tPassword:\t'+pwd+'\n')
oCookie.login(usr, pwd)
if not(oCookie.getUser()==usr):
	print(oCookie.getUser()+' is not the correct user name!\t\t\t\t\tFAILED')
else:
	print(oCookie.getUser()+' is the correct user name!\t\t\t\t\tSUCCESS')
if not(oCookie.getPassword()==pwd):
	print(oCookie.getPassword()+' is not the correct password!\t\t\t\t\tFAILED')
else:
	print(oCookie.getPassword()+' is the correct password!\t\t\t\t\tSUCCESS')
print('Login data test!\t\t\t\t\t\t\tFINISHED')
print('--------------------------------------------------------------------------------')
print('Check key value funktions!\n')
print('Testdata:')
key = 'Auto'
value = 'Porsche'
print('\tKey:\t'+key)
print('\tValue:\t'+value+'\n')
oCookie.addValue(key, value)
print('Key and value added!\t\t\t\t\t\t\tSUCCESS')
if oCookie.hasKey(key)==1:
	print('hasKey!\t\t\t\t\t\t\t\t\tSUCCESS')
else:
	print('hasKey!\t\t\t\t\t\t\t\t\tFAILED')
	sys.exit(0)
if oCookie.getValue(key)==value:
	print(oCookie.getValue(key)+' is the correct value!\t\t\t\t\t\tSUCCESS')
else:
	print(oCookie.getValue(key)+' is not the correct  value!\t\t\t\t\t\tFAILED')
oCookie.deleteValue(key)
print('Value deleted!\t\t\t\t\t\t\t\tSUCCESS')
print('Check key value functions!\t\t\t\t\t\tFINISHED')
print('--------------------------------------------------------------------------------')
print('Test crypt cookie with update expiration!\n')
oCookie = ccookie.ccookie(updateExpiration = True)
strExpiration = oCookie._ccookie__cookie['session']['expires']
sleep(5)
oCookie.login(usr, pwd)
if strExpiration != oCookie._ccookie__cookie['session']['expires']:
	print('Update expiration is working!\t\t\t\t\t\tSUCCESS')
else:
	print('Update expiration is not working!\t\t\t\t\tFAILED')
print('Test of update expiration!\t\t\t\t\t\tFINISHED')
print('--------------------------------------------------------------------------------')
print('Test for different expiration times!\n')
oCookie = ccookie.ccookie()
strExpectedExpiration = (datetime.datetime.now() + datetime.timedelta(minutes=15)).strftime("%a, %d-%b-%Y %H:%M:%S PST")
if strExpectedExpiration == oCookie._ccookie__cookie['session']['expires']:
	print('Default setting with expiration of 15 minutes is working!\t\tSUCCESS')
else:
	print('Default setting with expiration of 15 minutes is not working!\t\tFAILED')
oCookie = ccookie.ccookie(timedeltaMinutes = None)
strExpectedExpiration = (datetime.datetime.now() + datetime.timedelta(days=90)).strftime("%a, %d-%b-%Y %H:%M:%S PST")
if strExpectedExpiration == oCookie._ccookie__cookie['session']['expires']:
	print('Setting with expiration of 3 month is working!\t\t\t\tSUCCESS')
else:
	print('Setting with expiration of 3 month is not working!\t\t\tFAILED')
oCookie = ccookie.ccookie(timedeltaMinutes = 60)
strExpectedExpiration = (datetime.datetime.now() + datetime.timedelta(minutes=60)).strftime("%a, %d-%b-%Y %H:%M:%S PST")
if strExpectedExpiration == oCookie._ccookie__cookie['session']['expires']:
	print('Setting with expiration of 60 minutes is working!\t\t\tSUCCESS')
else:
	print('Setting with expiration of 60 minutes is not working!\t\t\tFAILED')
print('Test for different expiration times!\t\t\t\t\tFINISHED')
print('--------------------------------------------------------------------------------')
print('Test with individual keys!\n')
oInitialVector = Random.new().read(AES.block_size)
oKey = ''.join(SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(32))
oCookie = ccookie.ccookie(AESKey=oKey, AESInitialVector=oInitialVector)
if oCookie.getKey() == oKey:
	print('Individual key correct set!\t\t\t\t\t\tSUCCESS')
else:
	print('Individual key not correct set!\t\t\t\t\t\tFAILED')
if oCookie.getInitialVector() == oInitialVector:
	print('Individual vector correct set!\t\t\t\t\t\tSUCCESS')
else:
	print('Individual vector not correct set!\t\t\t\t\tFAILED')
print('Test with indiviual keys!\t\t\t\t\t\tFINISHED')
print('Simple Session ID tests FINISHED\n')
