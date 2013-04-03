import socket
import sys
 
HOST = 'localhost'
GET = '/rss.xml'
PORT = 6500
 
try:
  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except socket.error, msg:
  sys.stderr.write("[ERROR] %s\n" % msg[1])
  sys.exit(1)
 
try:
  sock.connect((HOST, PORT))
except socket.error, msg:
  sys.stderr.write("[ERROR] %s\n" % msg[1])
  sys.exit(2)
 
sock.send("GET %s HTTP/1.0\r\nHost: %s\r\n\r\n" % (GET, HOST))
 
data = sock.recv(1024)
string = ""
while len(data):
  string = string + data
  data = sock.recv(1024)
sock.close()
 
print string
 
sys.exit(0)