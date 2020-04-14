CFLAGS= -std=c99 -Wextra -Werror -Wall -pedantic

tr:
	gcc -o d6r d6r.c -lpcap -Wall -Wextra -pedantic

clean:
	-rm d6r
run:
	./d6r -i enp0s8

not:
	./d6r -s 2001:67c:1220:80c::93e5:dd2 -d
kill:
	killall d6r
ag:
	make kill
	make 
	make not
convpn:
	openvpn --config FIT.ovpn
