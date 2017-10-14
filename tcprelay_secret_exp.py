#!/usr/bin/python
#
# This is the relay script mentioned in http://blog.zorinaq.com/?e=81
#
# Listens on the address and port specified by --local-ip and --local-port, and
# relay all connections to the endpoint specified by --remote-hosts and
# --remote-port. Multiple remote hosts can be specified: one will be selected
# randomly for each connection.
#
# Optionally, if --mode 1:<secret> is specified, insert the secret key as the
# first bytes of data transmitted through each relayed connection, and if
# --mode 2:<secret> is specified, verify and remove the secret key (ignore
# the connection by discarding all data if the key does not match).
#
# I recommend a long hex string for the secret, for example:
# $ secret=`ps aux | md5sum | cut -c 1-32`
# $ ./tcprelay-secret-exp.py [...] -m 1:"$secret"

#import asyncake
import asyncore
import socket, random, struct
import re, os

class forwarder(asyncore.dispatcher):
    def __init__(self, ip, port, remoteip, remoteport, mode, secret, backlog=600):
        asyncore.dispatcher.__init__(self)
        self.remoteip=remoteip
        self.remoteport=remoteport
        self.mode=mode
        self.secret=secret
        self.create_socket(socket.AF_INET,socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind((ip,port))
        self.listen(backlog)

    def handle_accept(self):
        conn, addr = self.accept()
        # print '--- Connect --- '
        sender(receiver(conn, addr[0], self.mode, self.secret),self.remoteip,self.remoteport, addr[0])

class receiver(asyncore.dispatcher):
    def __init__(self, conn, client_ip, mode, secret):
        asyncore.dispatcher.__init__(self,conn)
        self.mode=mode
        self.secret=secret
        self.from_remote_buffer=''
        self.to_remote_buffer=''
        self.sender=None
        self.client_ip = client_ip
        self.zero_bytes_forwarded = True
        # for framing
        self.look_for_type = True
        self.field_type = None
        self.look_for_len_byte_nr = None
        self.field_len = None
        self.bytes_left_to_extract = None

    def handle_connect(self):
        pass

    def detect_and_remove_framing(self, read):
        processed_read = ''
        for b in read:
            if self.look_for_type:
                self.field_type = b
                self.look_for_type = False
                self.look_for_len_byte_nr = 0
                self.field_len = 0
            elif self.look_for_len_byte_nr != None:
                self.field_len <<= 8
                self.field_len += ord(b)
                self.look_for_len_byte_nr += 1
                if self.look_for_len_byte_nr >= 2:
                    self.look_for_len_byte_nr = None
                    self.bytes_left_to_extract = self.field_len
            elif self.bytes_left_to_extract != None:
                if self.field_type == 'd':
                    processed_read += b
                else:
                    pass
                self.bytes_left_to_extract -= 1
                if self.bytes_left_to_extract == 0:
                    self.bytes_left_to_extract = None
                    self.look_for_type = True
        return processed_read

    def handle_read(self):
        """Read from TCP client."""
        read = self.recv(4096)
        if self.mode == '1': # insert the secret key
            # Implement simple framing ('d' for data packets, 'p' for padding packets)
            read = 'd' + struct.pack('>h', len(read)) + read
            rlen = 0
            padding = 1
            if padding == 0: # no padding
                rlen = 0
            elif padding == 1 and len(read) < 1500: # padding
                if len(read) < 1000:
                    rlen = random.randint(1000 - len(read), 1500 - len(read))
                else:
                    rlen = random.randint(0, 1500 - len(read))
            if rlen:
                read += 'p' + struct.pack('>h', rlen) + os.urandom(rlen)
            if self.zero_bytes_forwarded:
                read = self.secret + read
                self.zero_bytes_forwarded = False
        elif self.mode == '2': # verify and remove the secret key
            if self.zero_bytes_forwarded:
                if read.startswith(self.secret):
                    read = read[len(self.secret):]
                    self.zero_bytes_forwarded = False
                else:
                    read = ''
            read = self.detect_and_remove_framing(read)
        # print '%04i -->'%len(read)
        self.from_remote_buffer += read

    def writable(self):
        return (len(self.to_remote_buffer) > 0)

    def handle_write(self):
        sent = self.send(self.to_remote_buffer)
        # print '%04i <--'%sent
        self.to_remote_buffer = self.to_remote_buffer[sent:]

    def handle_close(self):
        self.close()
        if self.sender:
            self.sender.close()

class sender(asyncore.dispatcher):
    def __init__(self, receiver, remoteaddr, remoteport, client_ip):
        asyncore.dispatcher.__init__(self)
        self.receiver=receiver
        receiver.sender=self
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connect((random.choice(remoteaddr), remoteport))

    def handle_connect(self):
        pass

    def handle_read(self):
        """Read from TCP server."""
        read = self.recv(4096)
        # print '<-- %04i'%len(read)
        self.receiver.to_remote_buffer += read

    def writable(self):
        return (len(self.receiver.from_remote_buffer) > 0)

    def handle_write(self):
        sent = self.send(self.receiver.from_remote_buffer)
        # print '--> %04i'%sent
        self.receiver.from_remote_buffer = self.receiver.from_remote_buffer[sent:]

    def handle_close(self):
        # when the buffer has not yet fully been written to the client, don't close quite yet.
        # handle_close() will be automatically called again by asyncore
        if not self.receiver.to_remote_buffer:
            self.close()
            self.receiver.close()

if __name__=='__main__':
    import optparse
    parser = optparse.OptionParser()

    parser.add_option(
            '-l','--local-ip',
            dest='local_ip',default='127.0.0.1',
            help='Local IP address to bind to (for listening socket)')
    parser.add_option(
            '-p','--local-port',
            type='int',dest='local_port',
            help='Local port to bind to')
    parser.add_option(
            '-P','--remote-port',
            type='int',dest='remote_port',
            help='Remote port to connect to')
    parser.add_option(
            '-r','--remote-hosts',
            type='string',dest='remote_hosts',default='127.0.0.1',
            help='Remote host(s) to connect to, comma-separated')
    parser.add_option(
            '-m','--mode',
            type='string',dest='mode',
            help='Operating mode ("0" for not using a secret key, ' + \
                    '"1:<secret>" for using/inserting the specified secret key, ' + \
                    '"2:<secret>" for verifying/stripping the specified secret key')
    options, args = parser.parse_args()
    alladdresses = {}
    for h in options.remote_hosts.split(','):
        (name, aliaslist, addresslist) = socket.gethostbyname_ex(h)
        for a in addresslist:
            alladdresses[a] = None
    if options.mode is None:
        (mode, secret) = (None, None)
    else:
        (mode, secret) = options.mode.split(':', 1)
        if len(secret) < 32:
            raise Exception('secret specified in -m option needs to be at least 32 characters long')
    #x = asyncake.AsynCake()
    forwarder(options.local_ip, options.local_port, alladdresses.keys(), options.remote_port, mode, secret)
    #x.loop()
    asyncore.loop()
