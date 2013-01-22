#!/usr/bin/python

import logging, sys, socket, subprocess, threading, time, os.path, os, signal, random
from ConfigParser import *
from getopt import getopt, GetoptError

class WinProxy():
	def enable(self, addr = None):
		with _winreg.OpenKey(_winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", 0, _winreg.KEY_ALL_ACCESS) as key:
			_winreg.SetValueEx(key, "ProxyEnable", None, _winreg.REG_DWORD, 1)

			if addr:
				_winreg.SetValueEx(key, "ProxyServer", None, _winreg.REG_SZ, addr)
	def disable(self):
		with _winreg.OpenKey(_winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", 0, _winreg.KEY_ALL_ACCESS) as key:
			_winreg.SetValueEx(key, "ProxyEnable", None, _winreg.REG_DWORD, 0)
	def get(self):
		with _winreg.OpenKey(_winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", 0, _winreg.KEY_ALL_ACCESS) as key:
			proxyServer = _winreg.QueryValueEx(key, "ProxyServer")[0]
			proxyEnabled = _winreg.QueryValueEx(key, "ProxyEnable")[0]
		return proxyServer, proxyEnabled

if sys.platform == 'win32':
	import _winreg
	g_proxy = WinProxy()

class Configure:
	def __init__(self, fname):
		defaultConfig = { 'clientType': 'plink', 'useForwardOrSocks': 'forward', 'username': 'nogfw', 'useDaemon': 'False', 'retriesInterval': '2', 'disableObfs2': 'False', 'sharedSecret': '', 'extraOpts': '', 'win32ProxySetting': 'True', 'startupPage': 'https://check.torproject.org/?lang=zh_CN' }
		config = ConfigParser(defaultConfig)
		config.read(fname)
		self.obfs2Addr = config.get('main', 'obfs2Addr')
		self.clientType = config.get('main', 'clientType')
		self.httpProxyForwardAddr = config.get('main', 'httpProxyForwardAddr')
		self.username = config.get('main', 'username')
		self.useForwardOrSocks = config.get('main', 'useForwardOrSocks')
		self.retriesInterval = config.getint('main', 'retriesInterval')
		self.sharedSecret = config.get('main', 'sharedSecret')
		self.disableObfs2 = config.getboolean('main', 'disableObfs2')
		self.extraOpts = config.get('main', 'extraOpts')
		self.win32ProxySetting = config.getboolean('main', 'win32ProxySetting')
		self.startupPage = config.get('main', 'startupPage')
		self.obfs2Path = config.get('path', 'Obfs2Path')
		self.clientPath = config.get('path', 'clientPath')
		self.verbose = config.getboolean('debug', 'verbose')

		try:
			self.SSHAddr= config.get('main', 'SSHAddr')
		except NoOptionError as e:
			self.SSHAddr = "localhost:%d" % (random.randint(1024, 65535))

		try:
			self.useDaemon = config.getboolean('main', 'useDaemon')
		except NoOptionError as e:
			self.useDaemon = False

		try:
			self.logFilename = config.get('main', 'logFilename')
		except NoOptionError as e:
			self.logFilename = None

		try:
			self.socksPort = config.getint('main', 'socksPort')
		except NoOptionError as e:
			self.socksPort = None

		try:
			self.keyFilePath = config.get('path', 'keyFilePath')
		except NoOptionError as e:
			self.keyFilePath = None

		assert(self.useForwardOrSocks.upper() == 'FORWARD' or self.useForwardOrSocks.upper() == 'SOCKS')
		assert(self.clientType.upper() == 'PLINK' or self.clientType.upper() == 'SSH')

		if self.useForwardOrSocks.upper() == 'SOCKS':
			assert(self.socksPort)

g_conf = None
g_quitting = False

def convertAddress(address):
	host, port = address.split(':')
	port = int(port)
	ip = socket.gethostbyname(host)

	return ip, port

def getSubprocessKwargs():
	kwargs = {}
	
	if g_conf.useDaemon:
		kwargs['stdout'] = open(os.devnull, 'w')
		kwargs['stderr'] = subprocess.STDOUT
	
	if subprocess.mswindows:
		su = subprocess.STARTUPINFO()
		su.dwFlags |= subprocess.STARTF_USESHOWWINDOW
		su.wShowWindow = subprocess.SW_HIDE
		kwargs['startupinfo'] = su

	return kwargs

def runCmd(cmd):
	cmdStr = " ".join(cmd).strip()
	logging.info("Executing: %s", cmdStr)
	retcode = subprocess.call(cmd, **getSubprocessKwargs())

	return retcode

g_obfsproxyProcess = None

def onRetriesDelay(retcode):
	if not g_quitting:
		logging.info("Terminated by error code %d, restarting in %d seconds...", retcode, g_conf.retriesInterval)
		time.sleep(g_conf.retriesInterval)

def execThr(cmd):
	global g_obfsproxyProcess

	while not g_quitting:
		cmdStr = " ".join(cmd).strip()
		logging.info("Executing: %s", cmdStr)
		g_obfsproxyProcess = subprocess.Popen(cmd, **getSubprocessKwargs())

		retcode = g_obfsproxyProcess.wait()
		onRetriesDelay(retcode)

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
	
	return configFn if configFn else "default.conf"

class NullDevice:
    def write(self, s):
        pass

def daemonize():
        sys.stdin.close()
        sys.stdout = NullDevice()
        sys.stderr = NullDevice()
        pid = os.fork()

        if pid == 0:
                os.setsid()
                pid = os.fork()

                if pid == 0:
                        os.umask(0)
                        os.chdir('/')
                else:
                        os._exit(0)
        else:
                os._exit(0)

def onSIGTERM(signum , stack_frame):
	cleanup()
	sys.exit(0)

def openBrowser():
	time.sleep(8)
	import webbrowser
	iexplore = os.path.join(os.environ.get("PROGRAMFILES", "C:\\Program Files"), "Internet Explorer\\IEXPLORE.EXE")
	ie = webbrowser.get(iexplore)
	ie.open(g_conf.startupPage)

def main():
	global g_conf
	global g_quitting

	configFn = parseArgv()
	g_conf = Configure(configFn)
	signal.signal(signal.SIGTERM, onSIGTERM)

	if g_conf.useDaemon:
		if g_conf.logFilename:
			logging.basicConfig(filename=g_conf.logFilename, level=logging.DEBUG if g_conf.verbose else logging.INFO, format='%(levelname)s - %(asctime)s %(message)s', datefmt='[%b %d %H:%M:%S]')
	else:
		logging.basicConfig(level=logging.DEBUG if g_conf.verbose else logging.INFO, format='%(levelname)s - %(asctime)s %(message)s', datefmt='[%b %d %H:%M:%S]')

	while True:
		try:
			g_conf.obfs2HostName, g_conf.obfs2Port = convertAddress(g_conf.obfs2Addr)
			g_conf.SSHHostName, g_conf.SSHPort = convertAddress(g_conf.SSHAddr)
			break
		except socket.gaierror as e:
			logging.info(e)

	del g_conf.obfs2Addr, g_conf.SSHAddr
	obfsproxyCmd = [ g_conf.obfs2Path, 'obfs2', '--dest=%s:%d' % (g_conf.obfs2HostName, g_conf.obfs2Port) ]

	if g_conf.sharedSecret:
		obfsproxyCmd += [ '--shared-secret=%s' % (g_conf.sharedSecret) ]

	obfsproxyCmd += [ 'client', '%s:%d' % (g_conf.SSHHostName, g_conf.SSHPort) ]

	if g_conf.useDaemon:
		if os.name == 'nt':
			raise RuntimeError('cannot be daemon in Windows')
		daemonize()

	if g_conf.disableObfs2:
		g_conf.SSHHostName, g_conf.SSHPort = g_conf.obfs2HostName, g_conf.obfs2Port
	else:
		runCmdInThread(obfsproxyCmd)

	if g_conf.win32ProxySetting and sys.platform == 'win32':
		if g_conf.useForwardOrSocks.upper() == 'FORWARD':
			tempAddr = g_conf.httpProxyForwardAddr.split(':')[0:2]

			if tempAddr[0] == '0.0.0.0':
				tempAddr[0] = '127.0.0.1'

			g_proxy.enable(':'.join(tempAddr))

		t = threading.Thread(target=openBrowser)
		t.daemon = True
		t.start()

	while not g_quitting:
		if not g_conf.disableObfs2:
			while not checkReachable(g_conf.SSHHostName, g_conf.SSHPort):
				time.sleep(0.5)

			logging.info("Obfsporxy connection %s:%s connected", g_conf.obfs2HostName, g_conf.obfs2Port)
			
		plinkCmd = [ g_conf.clientPath ]

		if g_conf.verbose:
			plinkCmd += [ '-v' ]

		if g_conf.extraOpts:
			plinkCmd += g_conf.extraOpts.split(' ')

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

		try:
			retcode = runCmd(plinkCmd)
			onRetriesDelay(retcode)
		except KeyboardInterrupt as e:
			g_quitting = True

import atexit

@atexit.register
def cleanup():
	global g_obfsproxyProcess 
	global g_quitting
	global g_proxy

	g_quitting = True

	if g_conf.win32ProxySetting and sys.platform == 'win32':
		g_proxy.disable()

	if g_obfsproxyProcess:
		logging.info("Cleanup Process %d", g_obfsproxyProcess.pid)
		g_obfsproxyProcess.terminate()
		time.sleep(1)

		if g_obfsproxyProcess.poll() is None:
			g_obfsproxyProcess.kill()

if __name__ == "__main__":
	main()
