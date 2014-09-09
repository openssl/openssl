CFLAGS_demos_state_machine=-I../../include -Wall -Werror -g

all: all_demos_state_machine
all_demos_state_machine: demos/state_machine/state_machine

demos/state_machine/state_machine: demos/state_machine/state_machine.o
	$(CC) -o demos/state_machine/state_machine demos/state_machine/state_machine.o -L. -lssl -lcrypto

test: test_demos_state_machine
test_demos_state_machine: demos/state_machine/state_machine
	demos/state_machine/state_machine 10000 apps/server.pem apps/server.pem

