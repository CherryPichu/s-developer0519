LDLIBS += -lpcap

All : main.c
	gcc -o deauth_attack main.c -lpcap
