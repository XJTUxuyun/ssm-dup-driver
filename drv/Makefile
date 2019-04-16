module := nm

KVERS = $(shell uname -r)
obj-m += $(module).o

#KVERS = 3.13.0-117-generic
default:
	make -C /lib/modules/$(KVERS)/build M=$(CURDIR) modules
