kldstat-stack-disclosure: kldstat-stack-disclosure.c
	$(CC) $(.ALLSRC) -Wall -Wpedantic -Werror -lm -o $(.TARGET)

clean:
	rm -f kldstat-stack-disclosure
