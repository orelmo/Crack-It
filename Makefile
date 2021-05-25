CC = gcc
LIBS = -lmta_rand -lmta_crypt -lcrypto -lpthread
SRCS := $(subst ./,,$(shell find . -maxdepth 1 -name "*.c"))
OBJS := $(patsubst %.c,%.out,$(SRCS))

all: $(OBJS)
	
%.out: %.c
	$(CC) $^ -o $@ $(LIBS) 
	
clean:
	find . -name "*.out" -exec rm {} \;