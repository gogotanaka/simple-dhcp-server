dhcp_server: server.o packet.o log.o ip_allocator.o
	cc -lpthread -lsqlite3 -g -o dhcp_server server.o packet.o log.o ip_allocator.o

server.o: dhcp_server.c ip_allocator.c dhcp_log.h dhcp_server.h dhcp_packet.h
	cc -g -c dhcp_server.c -o server.o

packet.o: dhcp_packet.c dhcp_log.h dhcp_packet.h
	cc -g -c dhcp_packet.c -o packet.o
	
log.o: dhcp_log.c dhcp_log.h
	cc -g -c dhcp_log.c -o log.o
ip_allocator.o: ip_allocator.c dhcp_server.h
	cc -lsqlite3 -g -c ip_allocator.c -o ip_allocator.o

clean:
	rm dhcp_server server.o packet.o log.o ip_allocator.o
