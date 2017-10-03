import ccookie
import os
import hashlib
import sys
from time import sleep

os.environ['SERVER_NAME']='Test Server Name'
os.environ['REMOTE_ADDR']='255.255.255.255'
print('\nSet enviroment variables!\n')
print('Server name set to "'+ os.environ['SERVER_NAME']+'" for the test routine!')
print('Remote address set to "' +os.environ['REMOTE_ADDR'] +'" for the test routine!\n')
print('Set enviroment variables!\t\tFINISHED')
print('-------------------------------------------------------------------------------')
print('Generate test crypt cookie!\n')
oCookie = ccookie.ccookie()
print('Generate test crypt cookei!\t\tFINISHED')
print('-------------------------------------------------------------------------------')
print('Test session data!\n')
print('Session:\t' + oCookie._ccookie__cookie['session'].value)
print('Domain:\t\t' + oCookie._ccookie__cookie['session']['domain'])
print('Path:\t\t' + oCookie._ccookie__cookie['session']['path'])
print('Expires:\t' + oCookie._ccookie__cookie['session']['expires'])
print('Encrypted IP:\t'+ oCookie._ccookie__cookie[str(oCookie._ccookie__toInt(oCookie._ccookie__encrypt('IP')))].value+'\n')
print('Test session data!\t\t\tFINISHED')
print('-------------------------------------------------------------------------------')
print('Validation test!\n')
if oCookie.isValid():
	print('Validation test!\t\t\tFINISHED')
else:
	print('Validation test!\t\t\tFAILED')
	sys.exit(0)
print('-------------------------------------------------------------------------------')
usr='Mad Max'
pwd='Donnerkupel'
print('Login data test!\n')
print('Testdata:')
print('\tUser name:\t'+usr)
print('\tPassword:\t'+pwd+'\n')
oCookie.login(usr, pwd)
if not(oCookie.getUser()==usr):
	print(oCookie.getUser()+' is not the correct user name!\tFAILED')
else:
	print(oCookie.getUser()+' is the correct user name!\tSUCCESS')
if not(oCookie.getPassword()==pwd):
	print(oCookie.getPassword()+' is not the correct password!\tFAILED')
else:
	print(oCookie.getPassword()+' is the correct password!\tSUCCESS')
print('Login data test!\t\t\tFINISHED')
print('-------------------------------------------------------------------------------')
print('Check key value funktions!\n')
print('Testdata:')
key = 'Auto'
value = 'Porsche'
print('\tKey:\t'+key)
print('\tValue:\t'+value+'\n')
oCookie.addValue(key, value)
print('Key and value added!\t\t\tSUCCESS')
if oCookie.hasKey(key)==1:
	print('hasKey!\t\t\t\t\tSUCCESS')
else:
	print('hasKey!\t\t\t\t\tFAILED')
	sys.exit(0)
if oCookie.getValue(key)==value:
	print(oCookie.getValue(key)+' is the correct value!\t\tSUCCESS')
else:
	print(oCookie.getValue(key)+' is not the correct  value!\t\tFAILED')
oCookie.deleteValue(key)
print('Value deleted!\t\t\t\tSUCCESS')
print('Check key value functions!\t\tFINISHED')
print('-------------------------------------------------------------------------------')
print('Test crypt cookie with update expiration\n')
oCookie = ccookie.ccookie(updateExpiration = True)
strExpiration = oCookie._ccookie__cookie['session']['expires']
sleep(5)
oCookie.login(usr, pwd)
if strExpiration != oCookie._ccookie__cookie['session']['expires']:
	print('Update expiration is working!\t\tSUCCESS')
else:
	print('Update expiration is not working!\tFAILED')
print('Test of update expiration!\t\tFINISHED')
print('All tests FINISHED')
