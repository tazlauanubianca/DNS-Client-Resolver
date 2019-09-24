SERVER=google.com
TYPE=A

CFLAGS = -Wall -g

default: dnsclient

dnsclient: dnsclient.c

run: dnsclient
	./dnsclient ${SERVER} ${TYPE}

.PHONY: clean

clean:
	rm -f dnsclient 
