cc := gcc

objects := agent.o

agent : agent.o
	cc -g -o agent $(objects)

agent.o : agent.c
	cc -g -c agent.c

.PHONY : clean
clean:
	-rm  agent 
	-rm *.o
