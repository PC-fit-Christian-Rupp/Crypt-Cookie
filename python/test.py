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
print('Encrypted IP:\t'+ a._ccookie__cookie[str(a._ccookie__toInt(a._ccookie__encrypt('IP')))].value+'\n')
print('Test session data!\t\t\tFINISHED')
print('-------------------------------------------------------------------------------')
print('Validation test!\n')
if a.isValid():
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
a.login(usr, pwd)
if not(a.getUser()==usr):
	print(a.getUser()+' is not the correct user name!\tFAILED')
else:
	print(a.getUser()+' is the correct user name!\tSUCCESS')
if not(a.getPassword()==pwd):
	print(a.getPassword()+' is not the correct password!\tFAILED')
else:
	print(a.getPassword()+' is the correct password!\tSUCCESS')
print('Login data test!\t\t\tFINISHED')
print('-------------------------------------------------------------------------------')
print('Check key value funktions!\n')
print('Testdata:')
key = 'Auto'
value = 'Porsche'
print('\tKey:\t'+key)
print('\tValue:\t'+value+'\n')
a.addValue(key, value)
print('Key and value added!\t\t\tSUCCESS')
if a.hasKey(key)==1:
	print('hasKey!\t\t\t\t\tSUCCESS')
else:
	print('hasKey!\t\t\t\t\tFAILED')
	sys.exit(0)
if a.getValue(key)==value:
	print(a.getValue(key)+' is the correct value!\t\tSUCCESS')
else:
	print(a.getValue(key)+' is not the correct  value!\t\tFAILED')
a.deleteValue(key)
print('Value deleted!\t\t\t\tSUCCESS')
print('Check key value functions!\t\tFINISHED')
print('All tests FINISHED')
