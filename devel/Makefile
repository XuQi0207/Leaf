
CC += -g -fPIC -D_LARGEFILE64_SOURCE
MTCCFLAGS = -pthread -DCTHREAD_LINUX -D_THREAD_SAFE -D_REENTRANT

BIN = /usr/bin

CP = cp
LD = cc
LN = ln

CNS_HOST = "vm083108.v.ihep.ac.cn"
CNSHOSTPFX = cns
INCLUDES = ../h

LIBS=../lib/libshift.a ../ns/libns.a

########################## FLAGS ##############################

CFLAGS =    -I$(INCLUDES) $(MTCCFLAGS) $(DFLAGS) $(RDSINC)

########################## DEPENDENCY LIBRARIES ###############


########################## RULES ##############################

CLIENT = myls 

all: $(CLIENT)
myls: myls.o 
	$(LD) -o $@ $(LDFLAGS) myls.o $(LIBS)
clean:
	rm -rf *.o $(CLIENT)
