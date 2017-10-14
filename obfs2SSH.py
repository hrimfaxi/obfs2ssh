#!/usr/bin/python2

import logging, sys, socket, subprocess, threading, time, os.path, os, signal, random, argparse
from ConfigParser import *

import tcprelay_secret_exp

def isWin32():
	return sys.platform == 'win32'

g_proxy = False

class Configure:
	DEFAULTCONFIG = {
			'clientType': 'plink',
			'useForwardOrSocks': 'forward',
			'username': 'nogfw',
			'retriesInterval': '15',
			'usePlainSSH': 'False',
			'sharedSecret': '',
			'extraOpts': '',
			'win32ProxySetting': 'True',
			'startupPage': 'http://www.ip138.com',
			'obfsProtocol': 'obfs2',
			'disableHostkeyAuth' : 'True'
	}
	def __init__(self, fname):
		config = ConfigParser(self.DEFAULTCONFIG)
		config.read(fname)
		conf_list = [
				[ "main", "obfs2Addr", "str" ],
				[ "main", "clientType", "str" ],
				[ "main", "httpProxyForwardAddr", "str" ],
				[ "main", "username", "str" ],
				[ "main", "useForwardOrSocks", "str" ],
				[ "main", "retriesInterval", "int" ],
				[ "main", "sharedSecret", "str" ],
				[ "main", "usePlainSSH", "bool" ],
				[ "main", "extraOpts", "str" ],
				[ "main", "win32ProxySetting", "bool" ],
				[ "main", "win32OpenBrowser", "bool", False ],
				[ "main", "startupPage", "str" ],
				[ "main", "obfsProtocol", "str" ],
				[ "main", "disableHostkeyAuth", "bool" ],
				[ "main", "useBandWidthObfs", "bool" ],
				[ "path", "obfs2Path", "str" ],
				[ "path", "clientPath", "str" ],
				[ "debug", "verbose", "bool" ],
				[ "main", "SSHAddr", "str", "localhost:%d" % (random.randint(1024, 65535)) ],
				[ "main", "logFilename", "str", None ],
				[ "main", "socksPort", "int", None ],
				[ "main", "bandwidthPort", "int", None ],
				[ "main", "bandwidthKey", "str", None ],
				[ "path", "keyFilePath", "str", None ],
				[ "path", "bandwidthPath", "str", None ],
				[ "path", "sysproxyPath", "str", None ],
		]

		for e in conf_list:
			if e[2] == "str":
				getter = config.get
			elif e[2] == "bool":
				getter = config.getboolean
			elif e[2] == "int":
				getter = config.getint
			try:
				setattr(self, e[1], getter(e[0], e[1]))
			except NoOptionError:
				if len(e) < 4:
					raise RuntimeError("%s: %s must be supplied" % (e[0], e[1]))
				else:
					setattr(self, e[1], e[3])

		if self.useForwardOrSocks.upper() != 'FORWARD' and self.useForwardOrSocks.upper() != 'SOCKS':
			raise RuntimeError("Invalid mode for useForwardOrSocks: %s" % (self.useForwardOrSocks))

		if self.clientType.upper() != 'PLINK' and self.clientType.upper() != 'SSH':
			raise RuntimeError("Invalid client type: %s" % (self.clientType))

		if self.useForwardOrSocks.upper() == 'SOCKS':
			if not self.socksPort:
				raise RuntimeError("Invalid sock5 port")

		if self.useBandWidthObfs:
			if self.bandwidthKey is None or len(self.bandwidthKey) != 32:
				raise RuntimeError("bandwidth obfs key should be 16 bytes hexstring")

g_conf = None

def getSubprocessKwargs():
	kwargs = {}

	# take control of stdin if host key auth is disabled
	if g_conf.disableHostkeyAuth:
		kwargs['stdin'] = subprocess.PIPE

	if subprocess.mswindows:
		su = subprocess.STARTUPINFO()
		su.dwFlags |= subprocess.STARTF_USESHOWWINDOW
		su.wShowWindow = subprocess.SW_HIDE
		kwargs['startupinfo'] = su

	return kwargs

class ProcessContainer:
	def __init__(self):
		self.quitting = False
		self.process = None
	def onRetriesDelay(self, retcode):
		if not self.quitting:
			logging.error("Terminated by error code %d, restarting in %d seconds...", retcode, g_conf.retriesInterval)
			doSleep()
	def run(self, cmd, beforeRun=None, afterRun=None):
		while not self.quitting:
			if beforeRun:
				beforeRun()

			cmdStr = " ".join(cmd).strip()
			logging.info("Executing: %s", cmdStr)
			self.process = subprocess.Popen(cmd, **getSubprocessKwargs())
			if afterRun:
				afterRun(self.process)
			self.process.communicate()
			retcode = self.process.wait()
			self.onRetriesDelay(retcode)
	def kill(self, name):
		self.quitting = True
		if self.process is None:
			return
		logging.info("Cleanup %s Process %d", name, self.process.pid)
		self.process.terminate()
		doSleep()

		if self.process.poll() is None:
			self.process.kill()

def runInBackground(cmd):
	c = ProcessContainer()
	runInBackgroundThread(c.run, (cmd,))
	return c

def runInBackgroundThread(func, args):
	t = threading.Thread(target=func, args=args)
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
		if conf.useBandWidthObfs:
			bandwithFoward = conf.httpProxyForwardAddr[:].split(':')
			if len(bandwithFoward) >= 4:
				bandwithFoward[1] = bandwithFoward[3] = str(conf.bandwidthPort)
			else:
				bandwithFoward[0] = bandwithFoward[2] = str(conf.bandwidthPort)

			plinkCmd += [ '-L', ':'.join(bandwithFoward) ]
		else:
			plinkCmd += [ '-L', conf.httpProxyForwardAddr ]
	else:
		plinkCmd += [ '-D', '%d'% (conf.socksPort) ]

	plinkCmd += [ '-P' if conf.clientType.upper() == 'PLINK' \
				else '-p', str(conf.SSHPort) ]

	plinkCmd += [ '%s@%s' % (conf.username, conf.SSHHostName) ]

	return plinkCmd

def generateObfsproxyCmd(conf):
	obfsproxyCmd = [ conf.obfs2Path, conf.obfsProtocol, '--dest=%s:%d' % (conf.obfs2HostName, conf.obfs2Port) ]

	if conf.sharedSecret:
		obfsproxyCmd += [ '--shared-secret=%s' % (conf.sharedSecret) ]

	obfsproxyCmd += [ 'client', '%s:%d' % (conf.SSHHostName, conf.SSHPort) ]

	return obfsproxyCmd

def setupLogger(conf):
	if conf.logFilename:
		logging.basicConfig(filename=conf.logFilename, level=logging.DEBUG if conf.verbose else logging.INFO, format='%(levelname)s - %(asctime)s %(message)s', datefmt='[%b %d %H:%M:%S]')
	else:
		logging.basicConfig(level=logging.DEBUG if conf.verbose else logging.INFO, format='%(levelname)s - %(asctime)s %(message)s', datefmt='[%b %d %H:%M:%S]')

def doSleep(t=1):
	time.sleep(t if t else g_conf.retriesInterval)

def resolveHost(address):
	while True:
		try:
			host, port = address.split(':')
			port = int(port)
			ip = socket.gethostbyname(host)
			break
		except socket.gaierror as e:
			logging.info(e)
			doSleep()
	return ip, port

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

g_obfsproxy = None

def waitForObfs():
	if not g_conf.usePlainSSH:
		while not checkReachable(g_conf.SSHHostName, g_conf.SSHPort, complex=False):
			doSleep()

		logging.info("Obfsporxy connection %s:%s connected", g_conf.obfs2HostName, g_conf.obfs2Port)

def writeYes(process):
	# write 'yes' if hostkey auth is disabled
	if g_conf.disableHostkeyAuth:
		process.stdin.write("yes\n")

def main():
	global g_conf
	global g_proxy
	global g_obfsproxy

	parser = argparse.ArgumentParser('obfs2ssh')
	parser.add_argument('config_filename', help='Configure file')

	args = parser.parse_args();
	g_conf = Configure(args.config_filename)
	signal.signal(signal.SIGTERM, onSIGTERM)
	setupLogger(g_conf)

	g_conf.obfs2HostName, g_conf.obfs2Port = resolveHost(g_conf.obfs2Addr)
	g_conf.SSHHostName, g_conf.SSHPort = resolveHost(g_conf.SSHAddr)
	del g_conf.obfs2Addr, g_conf.SSHAddr
	obfsproxyCmd = generateObfsproxyCmd(g_conf)

	if g_conf.usePlainSSH:
		g_conf.SSHHostName, g_conf.SSHPort = g_conf.obfs2HostName, g_conf.obfs2Port
	else:
		g_obfsproxy = runInBackground(obfsproxyCmd)

	if g_conf.useBandWidthObfs:
		splited = g_conf.httpProxyForwardAddr.split(':')
		if len(splited) <= 3:
			proxy_port = splited[0]
		else:
			proxy_port = splited[1]
		def bandwidth_thread():
			tcprelay_secret_exp.forwarder('127.0.0.1', int(proxy_port), ['127.0.0.1'], g_conf.bandwidthPort, '1', g_conf.bandwidthKey)
			tcprelay_secret_exp.asyncore.loop()
		runInBackgroundThread(bandwidth_thread, tuple())

	if g_conf.win32ProxySetting:
		logging.info("Setup Proxy")
		if g_conf.useForwardOrSocks.upper() == 'FORWARD':
			tempAddr = getHttpForwardAddress(g_conf)
			tempAddr[1] = str(tempAddr[1])
			tempAddr = ':'.join(tempAddr)
		elif g_conf.useForwardOrSocks.upper() == 'SOCKS':
			tempAddr = getSocks5Address(g_conf)
			tempAddr[1] = str(tempAddr[1])
			tempAddr = ':'.join(tempAddr)
			tempAddr = "socks=" + tempAddr
		sysproxy_cmd = [ g_conf.sysproxyPath, 'global', tempAddr,
				'<local>;localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;172.32.*;192.168.*'
				]
		logging.debug(' '.join(sysproxy_cmd))
		rc = subprocess.call(sysproxy_cmd)
		if rc == 0:
			g_proxy = True

	if g_conf.win32OpenBrowser:
		t = threading.Thread(target=openBrowser)
		t.daemon = True
		t.start()

	plink = ProcessContainer()
	plinkCmd = generatePlinkOrSSHCmd(g_conf)
	try:
		plink.run(plinkCmd, beforeRun=waitForObfs, afterRun=writeYes)
	except KeyboardInterrupt as e:
		plink.quitting = True

import atexit

@atexit.register
def cleanup():
	global g_obfsproxy
	global g_proxy
	global g_conf

	if g_conf is None:
		return

	if g_proxy:
		logging.info("Disable Proxy Settings")
		subprocess.call([ g_conf.sysproxyPath, 'global', ''])

	if g_obfsproxy:
		g_obfsproxy.kill("Obfsproxy")

if __name__ == "__main__":
	main()

# vim: set tabstop=4 sw=4 noexpandtab :
