FILE=create-stack

OBJS=${FILE}.o procmapsutils.o custom-loader.o

gdb: a.out
	gdb --args ./$<

procmapsutils.o: procmapsutils.c
	gcc -g3 -O0 -I. -c $< -o $@

custom-loader.o: custom-loader.c
	gcc -g3 -O0 -I. -c $< -o $@

${FILE}.o: ${FILE}.c
	gcc -DSTANDALONE -g3 -O0 -I. -c $< -o $@

a.out: ${OBJS}
	gcc -g3 -O0 -static -I. $^ -o $@

vi vim:
	vim ${FILE}.c

dist: clean
	(dir=`basename $$PWD` && cd .. && tar zcvf $$dir.tgz $$dir)
	(dir=`basename $$PWD` && ls -l ../$$dir.tgz)

clean:
	rm -f a.out ${OBJS}

.PHONY: dist vi vim clean gdb
