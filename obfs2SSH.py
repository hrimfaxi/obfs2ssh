#!/usr/bin/python2

import logging, sys, socket, subprocess, threading, time, os.path, os, signal, random, argparse
from ConfigParser import *

class WinProxy():
	def enable(self, addr = None):
		with _winreg.OpenKey(_winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", 0, _winreg.KEY_ALL_ACCESS) as key:
			_winreg.SetValueEx(key, "ProxyEnable", None, _winreg.REG_DWORD, 1)

			if addr:
				_winreg.SetValueEx(key, "ProxyServer", None, _winreg.REG_SZ, addr)
	def enableSocks5(self, addr):
		self.enable("socks=" + addr)
	def disable(self):
		with _winreg.OpenKey(_winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", 0, _winreg.KEY_ALL_ACCESS) as key:
			_winreg.SetValueEx(key, "ProxyEnable", None, _winreg.REG_DWORD, 0)
	def get(self):
		with _winreg.OpenKey(_winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", 0, _winreg.KEY_ALL_ACCESS) as key:
			proxyServer = _winreg.QueryValueEx(key, "ProxyServer")[0]
			proxyEnabled = _winreg.QueryValueEx(key, "ProxyEnable")[0]
		return proxyServer, proxyEnabled

def isWin32():
	return True if sys.platform == 'win32' else False

if isWin32():
	import _winreg
	g_proxy = WinProxy()

class Configure:
	def __init__(self, fname):
		defaultConfig = { 'clientType': 'plink', 'useForwardOrSocks': 'forward', 'username': 'nogfw', 'useDaemon': 'False', 'retriesInterval': '15', 'disableObfs2': 'False', 'sharedSecret': '', 'extraOpts': '', 'win32ProxySetting': 'True', 'startupPage': 'https://check.torproject.org/?lang=zh_CN', 'obfsProtocol': 'obfs2', 'disableHostkeyAuth' : 'True' }
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
		self.obfsProtocol = config.get('main', 'obfsProtocol')
		self.obfs2Path = config.get('path', 'Obfs2Path')
		self.clientPath = config.get('path', 'clientPath')
		self.verbose = config.getboolean('debug', 'verbose')
		self.disableHostkeyAuth = config.getboolean('main', 'disableHostkeyAuth')

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

		if self.useForwardOrSocks.upper() != 'FORWARD' and self.useForwardOrSocks.upper() != 'SOCKS':
			raise RuntimeError("Invalid mode for useForwardOrSocks: %s" % (self.useForwardOrSocks))

		if self.clientType.upper() != 'PLINK' and self.clientType.upper() != 'SSH':
			raise RuntimeError("Invalid client type: %s" % (self.clientType))

		if self.useForwardOrSocks.upper() == 'SOCKS':
			if not self.socksPort:
				raise RuntimeError("Invalid sock5 port")

g_conf = None
g_quitting = False

def convertAddress(address):
	host, port = address.split(':')
	port = int(port)
	ip = socket.gethostbyname(host)

	return ip, port

def getSubprocessKwargs():
	kwargs = {}

	# take control of stdin if host key auth is disabled
	if g_conf.disableHostkeyAuth:
		kwargs['stdin'] = subprocess.PIPE
	
	if g_conf.useDaemon:
		kwargs['stdout'] = open(os.devnull, 'w')
		kwargs['stderr'] = subprocess.STDOUT
	
	if subprocess.mswindows:
		su = subprocess.STARTUPINFO()
		su.dwFlags |= subprocess.STARTF_USESHOWWINDOW
		su.wShowWindow = subprocess.SW_HIDE
		kwargs['startupinfo'] = su

	return kwargs

def runPlinkOrSSH(cmd):
	cmdStr = " ".join(cmd).strip()
	logging.info("Executing: %s", cmdStr)
	p = subprocess.Popen(cmd, **getSubprocessKwargs())

	# write 'yes' if hostkey auth is disabled
	if g_conf.disableHostkeyAuth:
		p.stdin.write("yes\n")

	p.communicate()
	p.wait()

	return p.returncode

g_obfsproxyProcess = None

def onRetriesDelay(retcode):
	if not g_quitting:
		logging.info("Terminated by error code %d, restarting in %d seconds...", retcode, g_conf.retriesInterval)
		doSleep()

def obfsproxyThread(cmd):
	global g_obfsproxyProcess

	while not g_quitting:
		cmdStr = " ".join(cmd).strip()
		logging.info("Executing: %s", cmdStr)
		g_obfsproxyProcess = subprocess.Popen(cmd, **getSubprocessKwargs())
		g_obfsproxyProcess.communicate()
		retcode = g_obfsproxyProcess.wait()
		onRetriesDelay(retcode)

def runObfsproxy(cmd):
	t = threading.Thread(target=obfsproxyThread, args=(cmd,))
	t.daemon = True
	t.start()

def checkReachable(ip, port, timeout=5, complex=True):
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(timeout)
		s.connect((ip, port))

		if complex:
			s.sendall('hello\n')
			l = s.recv(16)

		s.close()

		if complex and len(l) == 0:
			return False
	except socket.error as e:
		return False

	return True

def usage():
	print ("%s: -f <config>" % (sys.argv[0]))

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

def waitUntilConnectionCompleted(conf):
	if conf.useForwardOrSocks.upper() == 'FORWARD':
		tempAddr = getHttpForwardAddress(conf)
	else:
		tempAddr = getSocks5Address(conf)
	
	#logging.debug("trying %s:%d", tempAddr[0], tempAddr[1])
	while not checkReachable(tempAddr[0], tempAddr[1], complex=False):
		doSleep()
	logging.debug('%s:%d connected', tempAddr[0], tempAddr[1])

def openBrowser():
	waitUntilConnectionCompleted(g_conf)
	import webbrowser
	iexplore = os.path.join(os.environ.get("PROGRAMFILES", "C:\\Program Files"), "Internet Explorer\\IEXPLORE.EXE")
	ie = webbrowser.get(iexplore)
	ie.open(g_conf.startupPage)

def generatePlinkOrSSHCmd(conf):
	plinkCmd = [ conf.clientPath ]

	if conf.verbose:
		plinkCmd += [ '-v' ]

	if conf.extraOpts:
		plinkCmd += conf.extraOpts.split(' ')

	plinkCmd += [ '-N' ]

	if conf.keyFilePath:
		plinkCmd += [ '-i', conf.keyFilePath ]
	
	if conf.useForwardOrSocks.upper() == 'FORWARD':
		plinkCmd += [ '-L', conf.httpProxyForwardAddr ]
	else:
		plinkCmd += [ '-D', '%d'% (conf.socksPort) ]

	plinkCmd += [ '-P' if conf.clientType.upper() == 'PLINK' \
				else '-p', '%d' % (conf.SSHPort) ] 

	plinkCmd += [ '%s@%s' % (conf.username, conf.SSHHostName) ]

	return plinkCmd

def generateObfsproxyCmd(conf):
	obfsproxyCmd = [ conf.obfs2Path, conf.obfsProtocol, '--dest=%s:%d' % (conf.obfs2HostName, conf.obfs2Port) ]

	if conf.sharedSecret:
		obfsproxyCmd += [ '--shared-secret=%s' % (conf.sharedSecret) ]

	obfsproxyCmd += [ 'client', '%s:%d' % (conf.SSHHostName, conf.SSHPort) ]

	return obfsproxyCmd

def setupLogger(conf):
	if conf.useDaemon:
		if conf.logFilename:
			logging.basicConfig(filename=conf.logFilename, level=logging.DEBUG if conf.verbose else logging.INFO, format='%(levelname)s - %(asctime)s %(message)s', datefmt='[%b %d %H:%M:%S]')
	else:
		logging.basicConfig(level=logging.DEBUG if conf.verbose else logging.INFO, format='%(levelname)s - %(asctime)s %(message)s', datefmt='[%b %d %H:%M:%S]')

def doSleep(t=1):
	time.sleep(t if t else g_conf.retriesInterval)

def resolveHostnameAndPort(obfs2Address, sshAddress):
	while True:
		try:
			obfs2Hostname, obfs2Port = convertAddress(obfs2Address)
			sshHostname, sshPort = convertAddress(sshAddress)
			break
		except socket.gaierror as e:
			logging.info(e)
			doSleep()

	return obfs2Hostname, obfs2Port, sshHostname, sshPort

def getHttpForwardAddress(conf):
	# returns http forward address like ['127.0.0.1', 3128]
	tempAddr = conf.httpProxyForwardAddr.split(':')

	if len(tempAddr) < 4:
		tempAddr.insert(0, '127.0.0.1')

	tempAddr = tempAddr[0:2]

	# Fixup address if it's 0.0.0.0
	if tempAddr[0] == '0.0.0.0':
		tempAddr[0] = '127.0.0.1'

	tempAddr[1] = int(tempAddr[1])

	return tempAddr

def getSocks5Address(conf):
	return ['localhost', conf.socksPort]

def main():
	global g_conf
	global g_quitting

	parser = argparse.ArgumentParser('obfs2ssh')
	parser.add_argument('config_filename', help='Configure file')

	args = parser.parse_args();
	configFn = args.configFn

	g_conf = Configure(configFn)
	signal.signal(signal.SIGTERM, onSIGTERM)
	setupLogger(g_conf)
	g_conf.obfs2HostName, g_conf.obfs2Port, g_conf.SSHHostName, g_conf.SSHPort = resolveHostnameAndPort(g_conf.obfs2Addr, g_conf.SSHAddr)
	del g_conf.obfs2Addr, g_conf.SSHAddr
	obfsproxyCmd = generateObfsproxyCmd(g_conf)

	if g_conf.useDaemon:
		if isWin32():
			raise RuntimeError('Cannot run as daemon in Windows')
		daemonize()

	if g_conf.disableObfs2:
		g_conf.SSHHostName, g_conf.SSHPort = g_conf.obfs2HostName, g_conf.obfs2Port
	else:
		runObfsproxy(obfsproxyCmd)

	if g_conf.win32ProxySetting and isWin32():
		if g_conf.useForwardOrSocks.upper() == 'FORWARD':
			tempAddr = getHttpForwardAddress(g_conf)
			tempAddr[1] = '%d'%(tempAddr[1])
			g_proxy.enable(':'.join(tempAddr))
		else:
			tempAddr = getSocks5Address(g_conf)
			tempAddr[1] = '%d'%(tempAddr[1])
			g_proxy.enableSocks5(':'.join(tempAddr))

		t = threading.Thread(target=openBrowser)
		t.daemon = True
		t.start()

	while not g_quitting:
		if not g_conf.disableObfs2:
			while not checkReachable(g_conf.SSHHostName, g_conf.SSHPort, complex=False):
				doSleep()

			logging.info("Obfsporxy connection %s:%s connected", g_conf.obfs2HostName, g_conf.obfs2Port)
		try:
			plinkCmd = generatePlinkOrSSHCmd(g_conf)
			retcode = runPlinkOrSSH(plinkCmd)
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

	if g_conf is None:
		return

	if g_conf.win32ProxySetting and isWin32():
		g_proxy.disable()

	if g_obfsproxyProcess:
		logging.info("Cleanup Process %d", g_obfsproxyProcess.pid)
		g_obfsproxyProcess.terminate()
		doSleep()

		if g_obfsproxyProcess.poll() is None:
			g_obfsproxyProcess.kill()

if __name__ == "__main__":
	main()

# vim: set tabstop=4 sw=4 noexpandtab :
