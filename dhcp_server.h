#ifndef _DHCP_SERVER_H
#define _DHCP_SERVER_H

#include<stdint.h>
#include<netinet/in.h>

#include "dhcp_packet.h"

#define BOOTP_REPLAY_PORT	68

#define BROADCAST_ADDRESS	"255.255.255.255"

#define	CONFIG_SERVER_ADDRESS 	"server"
#define CONFIG_LISTEN_PORT 		"listen_port"
#define CONFIG_LEASE_TIME		"lease_time"
#define	CONFIG_RENEW_TIME		"renew_time"
#define CONFIG_IP_ALLOCATOR_FILE	"ip_allocator_file"

struct server_config
{
	char 		server[16];
	uint16_t	port;
	uint32_t	lease;
	uint32_t	renew;
	char		ip_allocator_file[256];
};

struct raw_msg
{
	char		buff[DHCP_MAX_MTU];
	uint32_t	length;
	struct sockaddr_in address;
	int socket_fd;
};

struct dhcp_packet *do_discover(struct dhcp_packet *request);

struct dhcp_packet *do_request(struct dhcp_packet *request);

struct dhcp_packet *do_release(struct dhcp_packet *request);

struct dhcp_packet *do_inform(struct dhcp_packet *request);

struct dhcp_packet *do_decline(struct dhcp_packet *request);

struct dhcp_packet_handler
{
	struct dhcp_packet *(*do_discover)(struct dhcp_packet *);
	struct dhcp_packet *(*do_inform)(struct dhcp_packet *);
	struct dhcp_packet *(*do_request)(struct dhcp_packet *);
	struct dhcp_packet *(*do_release)(struct dhcp_packet *);
	struct dhcp_packet *(*do_decline)(struct dhcp_packet *);
};

int ip_asc2bytes(char bytes[], char* ip_address);

int start_server(char *config_file);

void *handle_msg(void *arg);

struct dhcp_packet *dispatch(struct dhcp_packet *request);

struct network_config
{
	char hardware_address[16];
	char ip_address[4];
	char router[4];
	char netmask[4];
	char dns1[4];
	char dns2[4];
};

typedef int (*ip_allocator)(struct network_config *);

#endif
