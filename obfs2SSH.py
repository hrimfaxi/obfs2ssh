#!/usr/bin/python

import logging, sys, socket, subprocess, threading, time
from ConfigParser import *
from getopt import getopt, GetoptError

class Configure:
	def __init__(self, fname):
		config = ConfigParser()
		config.read(fname)

		self.obfs2Addr = config.get('main', 'obfs2Addr')
		self.SSHAddr= config.get('main', 'SSHAddr')
		self.clientType = config.get('main', 'clientType')
		self.httpProxyForwardAddr = config.get('main', 'httpProxyForwardAddr')
		self.username = config.get('main', 'username')
		self.useForwardOrSocks = config.get('main', 'useForwardOrSocks')

		try:
			self.socksPort = config.getint('main', 'socksPort')
		except NoOptionError as e:
			self.socksPort = None

		assert(self.useForwardOrSocks.upper() == 'FORWARD' or self.useForwardOrSocks.upper() == 'SOCKS')

		if self.useForwardOrSocks.upper() == 'SOCKS':
			assert(self.socksPort)

		assert(self.clientType.upper() == 'PLINK' or self.clientType.upper() == 'SSH')

		self.obfs2Path = config.get('path', 'Obfs2Path')
		self.clientPath = config.get('path', 'clientPath')

		try:
			self.keyFilePath = config.get('path', 'keyFilePath')
		except NoOptionError as e:
			self.keyFilePath = None

		self.verbose = config.getboolean('debug', 'verbose')

g_conf = None

def convertAddress(address):
	host, port = address.split(':')
	port = int(port)
	ip = socket.gethostbyname(host)

	return ip, port

def runCmd(cmd):
	cmdStr = " ".join(cmd).strip()
	logging.info("Executing: %s", cmdStr)
	retcode = subprocess.call(cmd)
	logging.info("Terminated by error code %d, restarting in 2 seconds...", retcode)

def execThr(cmd):
	while True:
		runCmd(cmd)
		time.sleep(2)

def runCmdInThread(cmd):
	t = threading.Thread(target=execThr, args=(cmd,))
	t.daemon = True
	t.start()

def checkReachable(ip, port):
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(1)
		s.connect((ip, port))
		s.close()
	except socket.error as e:
		return False

	return True

def usage():
	print ("%s: -f <config>" % (sys.argv[0]))

def parseArgv():
	configFn = None

	try:
		optlist, args = getopt(sys.argv[1:], 'f:')

		for o, a in optlist:
			if o == '-f':
				configFn = a
	except GetoptError as e:
		print str(e)
		usage()
		sys.exit(2)

	if configFn == None:
		print str(e)
		usage()
		sys.exit(2)
	
	return configFn

def main():
	global g_conf

	configFn = parseArgv()
	g_conf = Configure(configFn)
	logging.basicConfig(level=logging.DEBUG if g_conf.verbose else logging.INFO, format='%(levelname)s - %(asctime)s %(message)s', datefmt='[%b %d %H:%M:%S]')
	g_conf.obfs2HostName, g_conf.obfs2Port = convertAddress(g_conf.obfs2Addr)
	g_conf.SSHHostName, g_conf.SSHPort = convertAddress(g_conf.SSHAddr)
	del g_conf.obfs2Addr, g_conf.SSHAddr
	obfsproxyCmd = [ g_conf.obfs2Path, 'obfs2', '--dest=%s:%d' % (g_conf.obfs2HostName, g_conf.obfs2Port), 'client', '%s:%d' % (g_conf.SSHHostName, g_conf.SSHPort) ]
	runCmdInThread(obfsproxyCmd)

	while not checkReachable(g_conf.SSHHostName, g_conf.SSHPort):
		time.sleep(1)

	logging.info("Obfsporxy connection %s:%s connected", g_conf.obfs2HostName, g_conf.obfs2Port)

	while True:
		plinkCmd = [ g_conf.clientPath ]

		if g_conf.verbose:
			plinkCmd += [ '-v' ]

		plinkCmd += [ '-N' ]

		if g_conf.keyFilePath:
			plinkCmd += [ '-i', g_conf.keyFilePath ]
		
		if g_conf.useForwardOrSocks.upper() == 'FORWARD':
			plinkCmd += [ '-L', g_conf.httpProxyForwardAddr ]
		else:
			plinkCmd += [ '-D', '%d'% (g_conf.socksPort) ]

		plinkCmd += [ '-P' if g_conf.clientType.upper() == 'PLINK' \
					else '-p', '%d' % (g_conf.SSHPort) ] 

		plinkCmd += [ '%s@%s' % (g_conf.username, g_conf.SSHHostName) ]
		runCmd(plinkCmd)
		time.sleep(1)

if __name__ == "__main__":
	main()
