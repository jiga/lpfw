WARN 	:= -W -Wall -Wstrict-prototypes -Wmissing-prototypes
INCLUDE	:= -I /lib/modules/`uname -r`/build/include
CFLAGS	:= -O2 -DMODULE -D__KERNEL__ ${INCLUDE}
CC	:= gcc

all: lkmpfw.o

lkmpfw.o: pfw.c  pfw.h
	${CC} ${CFLAGS} -c pfw.c -o lkmpfw.o

.PHONY: clean

clean:
	rm -Rf *.o 

install:
	insmod ./lkmpfw.o

uninstall:
	rmmod lkmpfw
 
