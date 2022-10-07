
#PATH=$PATH:/usr/bin/
PATH=$PATH:/usr/local/angstrom/armv7linaro/bin/
BIN_PATH = /home/ubobrov/develop/projects/intercom/rootfs/root

CROSS_COMPILE ?=arm-linux-gnueabihf-

CC = $(CROSS_COMPILE)gcc

CP = /bin/cp
DEL = /bin/rm -f

APP = nanosip
MKFILE = Makefile

SRC = main.c nanosip.c md5.c random.c pkt.c rtp.c

OBJS = $(SRC:.c=.o)
DEPS = $(SRC:.c=.d)

LIBDIR = 

CPFLAGS = -DDEBUG -DOS_LINUX

LDFLAGS = -lpthread

.PHONY: all target
target: all

all: $(OBJS) $(MKFILE)
	$(CC) $(OBJS) -o $(APP) $(LDFLAGS)
	-$(CP) $(APP) $(BIN_PATH)
	

%.o: %.c $(MKFILE)
	@echo "Compiling '$<'"
	$(CC) -c $(CPFLAGS) -I . $< -o $@

%.d: %.c $(MKFILE)
	@echo "Building dependencies for '$<'"
	@$(CC) -E -MM -MQ $(<:.c=.o) $(CPFLAGS) $< -o $@
	@$(DEL) $(<:.c=.o)
	
clean:
	-$(DEL) $(OBJS:/=\)
	-$(DEL) $(DEPS:/=\)
	-$(DEL) $(APP:/=\)

	
.PHONY: dep
dep: $(DEPS) $(SRC)
	@echo "##########################"
	@echo "### Dependencies built ###"
	@echo "##########################"

-include $(DEPS)
