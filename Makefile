FILE=create-stack

RTLD_PATH=/lib64/ld-2.27.so

OBJS=${FILE}.o procmapsutils.o custom-loader.o

gdb: a.out t.out
	TARGET_LD=${RTLD_PATH} TARGET_APP=$$PWD/t.out gdb --args ./$<

procmapsutils.o: procmapsutils.c
	gcc -g3 -O0 -I. -c $< -o $@

custom-loader.o: custom-loader.c
	gcc -g3 -O0 -I. -c $< -o $@

${FILE}.o: ${FILE}.c
	gcc -DSTANDALONE -std=gnu11 -g3 -O0 -I. -c $< -o $@

t.out: target.o # Target application
	gcc -g3 -O0 $< -o $@

target.o: target.c # Target application
	gcc -g3 -O0 -I. -c $< -o $@

a.out: ${OBJS}
	gcc -Wl,-Ttext-segment -Wl,0x800000 -g3 -O0 -static -I. $^ -o $@

vi vim:
	vim ${FILE}.c

dist: clean
	(dir=`basename $$PWD` && cd .. && tar zcvf $$dir.tgz $$dir)
	(dir=`basename $$PWD` && ls -l ../$$dir.tgz)

clean:
	rm -f a.out ${OBJS} target.o t.out

.PHONY: dist vi vim clean gdb
