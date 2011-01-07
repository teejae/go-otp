include $(GOROOT)/src/Make.inc

TARG=otpclient
GOFILES=\
	otpclient.go\

DEPS=otp

include $(GOROOT)/src/Make.pkg