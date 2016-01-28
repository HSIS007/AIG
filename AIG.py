print "#" * 50
print "#" * 50
print      " ##       #########   ######### "
print     " #  #          #       #         "
print    " #    #         #       #         "
print   " ########        #       ######### "
print  " #        #       #               # "
print " #          #  #########           # V1.0 "   
print " Created by HSIS007 AKA(SZZER)"
print " Active Information Gathering tool for pentester, so far this script connects to the host and informs the pentester about the banner on the selected port."
import optparse
import socket
from socket import*
from threading import* 
screenLock = Semaphore(value = 1)
def connection(Host,Port): #Takes two arguments host and port
	try:
		fetchSkt = socket(AF_INET,SOCK_STREAM) #this creates object with IPv4 and tcp connection
		
		fetchSkt.connect((Host,Port))  #attempt to create connection to host and port
		fetchSkt.send('goandchecktheport\r\n') #attempt to send a string of data to port and wait for response
		results = fetchSkt.recv(100) #attempt to recieve the response
		screenLock.acqire()
		print '[+]%d/tcp open'% Port # print an open port if succcess
		print '[+] ' + str(results)
	except:
		screenLock.acquire()
		print '[-]%d/tcp closed'% Port # print closed port if unscccessfull
	finally:
		screenLock.release()
		fetchSkt.close()	
def portScan(Host,Ports):   #This function takes the hostname and targetport as arguments
	try: 
		fetchIP = gethostbyname(Host) # resolve an IP address to hostname
	except:
		print "[-] Cannot Resolve ' %s ' :Unknown host "% Host
		return
	try:
		fetchName = gethostbyaddr(fetchIP) #It would print the hostname
		print '\n[+] Scan results for: '+ fetchName[0]
	except:
		print '\n[+] Scan results for: '+ fetchIP
	setdefaulttimeout(1)
	for Port in Ports:
		t = Thread(target = connection, args=(Host, int(Port)))
		t.start()
def main():
	parser = optparse.OptionParser('usage AIG.py -H <IP Address host> -p <target port>') #Creates an instance of an option parser
	parser.add_option('-H',dest='Host',type='string',help='specify target host') #Specifies the individual command line options for script
	parser.add_option('-p',dest='Port',type='string',help='enter port to scan for')
	(options,args) = parser.parse_args()
	Host = options.Host
	Ports = str(options.Port).split(', ')
	if (Host == None)| (Ports[0] == None):
		print parser.usage
#		print '[-] You must specify a target host and port[s].'
		exit(0)
	portScan(Host, Ports)
if __name__=='__main__':
	main()
