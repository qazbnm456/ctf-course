

all: vuln1 vuln2 alarm_hook.so

alarm_hook.so: alarm_hook.c
	gcc alarm_hook.c -o alarm_hook.so -m32 -fPIC -shared

vuln1: vuln1.c
	gcc vuln1.c -o vuln1 -m32 -fno-stack-protector

vuln2: vuln2.c
	gcc vuln2.c -o vuln2 -m32 -fno-stack-protector


