CFLAGS = -Wall
CC = gcc
LDFLAGS = -pthread -lmta_crypt -lcrypto -lmta_rand
ECHO = echo "going to compile for target $@"
PROG = Linux_ex2_mta_crypto
OBJFILES =  Linux_ex2_mta_crypto.o

all: $(PROG) 

%.o: %.c
# $<: automatic variable for dependency (%.c)
# $@: automatic variable for target (%.o)
	@$(ECHO)
	$(CC) $(CFLAGS) -c $< -o $@	

$(PROG): $(OBJFILES)
	@$(ECHO)
	$(CC) -o $(PROG) $(CFLAGS) $(OBJFILES) $(LDFLAGS)
 
.PHONY: clean
clean:
	rm -vf *.o $(PROG) *.log *.tmp