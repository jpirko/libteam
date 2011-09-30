CC=gcc
CFLAGS=-I/usr/local/include/libnl3/ -I.
LIBS=-lnl-3 -lnl-genl-3 -lnl-cli-3
APPS=team_monitor team_manual_control

%.o: %.c $(DEPS)
		$(CC) -c -o $@ $< $(CFLAGS)

all: $(APPS)

team_manual_control: libteam.o team_manual_control.o 
		$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

team_monitor: libteam.o team_monitor.o 
		$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

clean:
	rm -f *.o $(APPS)
