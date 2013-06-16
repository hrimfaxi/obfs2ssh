#!/usr/bin/python

import random
import string

SECRET_LENGTH = 32

if __name__ == "__main__":
	print "Random port: %d" % (random.randint(1024, 65535))
	print (''.join([random.choice(string.digits + string.letters) for i in range(SECRET_LENGTH)]))
