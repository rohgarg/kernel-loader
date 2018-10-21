FILE=kernel-loader

RTLD_PATH=/lib64/ld-2.27.so

KERNEL_LOADER_OBJS=${FILE}.o procmapsutils.o custom-loader.o mmap-wrapper.o sbrk-wrapper.o
TARGET_OBJS=target.o

CFLAGS=-g3 -O0 -fPIC -I. -c -std=gnu11
KERNEL_LOADER_CFLAGS=-DSTANDALONE

KERNEL_LOADER_BIN=kernel-loader
TARGET_BIN=t.out

run: kernel-loader t.out
	TARGET_LD=${RTLD_PATH} ./$< $$PWD/t.out arg1 arg2 arg3

gdb: kernel-loader t.out
	TARGET_LD=${RTLD_PATH} gdb --args ./$< $$PWD/t.out arg1 arg2 arg3

.c.o:
	gcc ${CFLAGS} $< -o $@

${FILE}.o: ${FILE}.c
	gcc ${CFLAGS} ${KERNEL_LOADER_CFLAGS} $< -o $@

${TARGET_BIN}: ${TARGET_OBJS}
	gcc $< -o $@

${KERNEL_LOADER_BIN}: ${KERNEL_LOADER_OBJS}
	gcc -Wl,-Ttext-segment -Wl,0x800000 -static $^ -o $@

vi vim:
	vim ${FILE}.c

tags:
	gtags .

dist: clean
	(dir=`basename $$PWD` && cd .. && tar zcvf $$dir.tgz $$dir)
	(dir=`basename $$PWD` && ls -l ../$$dir.tgz)

clean:
	rm -f ${KERNEL_LOADER_OBJS} ${TARGET_OBJS} ${KERNEL_LOADER_BIN} ${TARGET_BIN} GTAGS GRTAGS GPATH

.PHONY: dist vi vim clean gdb tags
