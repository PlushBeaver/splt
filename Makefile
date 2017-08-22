.PHONY: all clear

product=splt

all: $(product)

$(product): splt.c Makefile
	gcc -std=c11 -D_GNU_SOURCE -O2 -lpcap -o $@ $<

clean:
	rm -f $(product)
