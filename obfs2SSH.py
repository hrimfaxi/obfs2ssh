#!/usr/bin/python

import logging, sys, socket, subprocess, threading, time
from ConfigParser import *
from getopt import getopt, GetoptError

VERSION='0.0'
PROG_NAME = "Obfs2SSH"

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

		assert(self.clientType == 'plink')

		self.obfs2Path = config.get('path', 'Obfs2Path')
		self.clientPath = config.get('path', 'clientPath')
		self.keyFilePath = config.get('path', 'keyFilePath', None)

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
	try:
		optlist, args = getopt(sys.argv[1:], 'f:')

		for o, a in optlist:
			if o == '-f':
				configFn = a
	except GetoptError as e:
		print str(e)
		usage()
		sys.exit(2)
	
	return configFn

def main():
	global g_conf

	configFn = parseArgv()
	g_conf = Configure(configFn)
	logging.basicConfig(level=logging.DEBUG if g_conf.verbose else logging.INFO, format='%(levelname)s - %(asctime)s %(message)s', datefmt='[%b %d %H:%M:%S]')
	logging.info("%s: version: %s", PROG_NAME, VERSION)

	g_conf.obfs2HostName, g_conf.obfs2Port = convertAddress(g_conf.obfs2Addr)
	logging.debug("obfs2 host: %s, port: %d", g_conf.obfs2HostName, g_conf.obfs2Port)

	g_conf.SSHHostName, g_conf.SSHPort = convertAddress(g_conf.SSHAddr)
	logging.debug("ssh host: %s, port: %d", g_conf.SSHHostName, g_conf.SSHPort)

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
		
		if g_conf.clientType == 'plink':
			plinkCmd += [ '-N' ]

			if g_conf.keyFilePath:
				plinkCmd += [ '-i', g_conf.keyFilePath ]

			if g_conf.useForwardOrSocks.upper() == 'FORWARD':
				plinkCmd += [ '-L', g_conf.httpProxyForwardAddr ]
			else:
				plinkCmd += [ '-D', '%d'% (g_conf.socksPort) ]

			plinkCmd += [ '-P', '%d' % (g_conf.SSHPort), '%s@%s' % (g_conf.username, g_conf.SSHHostName)]
		elif g_conf.clientType == 'ssh':
			raise RuntimeError("TODO %s" %(g_conf.clientType))
		else:
			raise RuntimeError("Unknown ssh client type %s" %(g_conf.clientType))

		runCmd(plinkCmd)
		time.sleep(1)

if __name__ == "__main__":
	main()
