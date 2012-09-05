#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<errno.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<pthread.h>

#include "dhcp_server.h"
#include "dhcp_log.h"

struct server_config gobal_config = {0};

struct dhcp_packet_handler gobal_packet_handler = 
{
	.do_discover	= &do_discover,
	.do_inform		= &do_inform,
	.do_request		= &do_request,
	.do_release		= &do_release,
	.do_decline		= &do_decline,
};

int ip_asc2bytes(char bytes[], char* ip_address)
{
	INFO("==>ip_asc2bytes, ip_address=%s", ip_address);

    if(NULL == ip_address || strlen(ip_address) > 15 || strlen(ip_address) < 7)
    {
        ERROR("***IP address is invalid, ip_asc2bytes==>***");
        return 0;
    }

    char buff[4] = {0};
    int buff_index = 0;
    int ret = 0;
    int i = 0;
    for(i = 0; '\0' != ip_address[i]; i++)
    {
        if('.' == ip_address[i])
        {
            buff[4] = '\0';
            bytes[ret++] = atoi(buff);
            memset(buff, 0, 4);
            buff_index = 0;
        }

        if(ip_address[i] >= '0' && ip_address[i] <= '9')
        {
            buff[buff_index++] = ip_address[i];
        }
    }

    if(buff_index > 0)
    {
        buff[4] = '\0';
        bytes[ret++] = atoi(buff);
    }
    INFO("ip_asc2bytes==>");
    return ret;
}

int start_server(char *config_file)
{
	INFO("==>start_server, config_file=%s", config_file);
	//parse configuration file
	FILE *file = fopen(config_file, "r");
	if(NULL == file)
	{
		FATAL("***Cannot open config_file!***, start_server==>");
		return -1;
	}
	char buffer[CONFIG_BUFFER_SIZE];

	while(!feof(file))
	{
		if(NULL != fgets(buffer, CONFIG_BUFFER_SIZE, file))
		{	
			DEBUG("read line from config file: %s", buffer);
			int index = 0;
			for(; '\0' != buffer[index] && '=' != buffer[index]; index++);

			if('\0' == buffer[index])
			{
				continue;
			}
			
			buffer[index] = '\0';
			char *value_begin = buffer + index + 1;
			int value_length = strlen(value_begin);
			if('\n' == value_begin[value_length - 1])
			{
				value_begin[value_length - 1] = '\0';
			}
			
			if(0 == strcmp(buffer, CONFIG_SERVER_ADDRESS))
			{
				strncpy(gobal_config.server, value_begin, 16);	
			}
			else if(0 == strcmp(buffer, CONFIG_LISTEN_PORT))
			{
				char value[6] = {0};
				strncpy(value, value_begin, 6);
				gobal_config.port = atoi(value);
			}
			else if(0 == strcmp(buffer, CONFIG_LEASE_TIME))
			{
				char value[11] = {0};
				strncpy(value, value_begin , 11);
				gobal_config.lease = atoi(value);
			}
			else if(0 == strcmp(buffer, CONFIG_RENEW_TIME))
            {
                char value[11] = {0} ;
                strncpy(value, value_begin , 11);
                gobal_config.renew = atoi(value);
            }
			else if(0 == strcmp(buffer, CONFIG_IP_ALLOCATOR_FILE))
			{
				strncpy(gobal_config.ip_allocator_file, value_begin, 256);
			}
		}	
	}
	
	fclose(file);

	if(NULL == gobal_config.server || 0 ==  gobal_config.port || 0 ==  gobal_config.lease || 0 ==  gobal_config.renew || NULL == gobal_config.ip_allocator_file)
	{
		goto ERROR;
	}

	DEBUG("-------DUMP GOBAL_CONFIG----------");
	DEBUG("gobal_config.server=%s", gobal_config.server);
	DEBUG("gobal_config.port=%d", gobal_config.port);
	DEBUG("gobal_config.lease=%d", gobal_config.lease);
	DEBUG("gobal_config.renew=%d", gobal_config.renew);
	DEBUG("-----------------END--------------");
	
	int dhcp_socket = 0;
	int so_reuseaddr = 1;
	struct sockaddr_in server_address;

	if((dhcp_socket = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	{
		FATAL("***Cannot open the socket! %s(%d)***", strerror(errno), errno);
		goto ERROR;
	}

	setsockopt(dhcp_socket, SOL_SOCKET, SO_REUSEADDR, &so_reuseaddr, sizeof(so_reuseaddr));
	
	memset(&server_address, 0, sizeof(server_address));
	server_address.sin_family = AF_INET;
	server_address.sin_port = htons(gobal_config.port);
	server_address.sin_addr.s_addr = htonl(INADDR_ANY);

	if(bind(dhcp_socket, (struct sockaddr*)&server_address, sizeof(server_address)) < 0)
	{
		FATAL("***Cannot bind the socket with the address! %s(%d)***", strerror(errno), errno);
		goto ERROR;
	}
	
	socklen_t addr_len = sizeof(struct sockaddr_in);
	while(1)
	{
		struct raw_msg *msg = (struct raw_msg*)malloc(sizeof(struct raw_msg));
		if(NULL == msg)
		{
			FATAL("***Allocate memory failed! %s(%d)***", strerror(errno), errno);
			continue;
		}
		memset(msg, 0, sizeof(struct raw_msg));
		msg->socket_fd = dhcp_socket;
		msg->length = recvfrom(dhcp_socket, msg->buff, DHCP_MAX_MTU, 0, (struct sockaddr*)&msg->address, &addr_len);
		DEBUG("%d bytes received", msg->length);
		if(msg->length < 0)
		{
			WARN("***Receive data error! %s(%d)***", strerror(errno), errno);
			free(msg);
			continue;
		}
		pthread_t thread_id;
		pthread_create(&thread_id, NULL, &handle_msg, (void *)msg);
	}
ERROR:
	if(0 != dhcp_socket)
	{
		close(dhcp_socket);
	}
	WARN("***error!*** marshall==>");
	return -1;
}

void *handle_msg(void *arg)
{
	INFO("==>handle_msg, arg=%d", arg);
	struct raw_msg *msg = (struct raw_msg*)arg;
	struct dhcp_packet *request = marshall(msg->buff, 0, msg->length);
	
	if(NULL != request)
	{
		struct dhcp_packet *response = dispatch(request);
		
		if(NULL != response)
		{
			int broadcast_socket = 0;
    		int so_broadcast = 1;
			int so_reuseaddr = 1;
    		struct sockaddr_in server_address;

    		if((broadcast_socket = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    		{
        		FATAL("***Cannot open the socket! %s(%d)***", strerror(errno), errno);
    			goto ERROR;		
    		}

    		setsockopt(broadcast_socket, SOL_SOCKET, SO_BROADCAST, &so_broadcast, sizeof(so_broadcast));
			setsockopt(broadcast_socket, SOL_SOCKET, SO_REUSEADDR, &so_reuseaddr, sizeof(so_reuseaddr));	
		
    		memset(&server_address, 0, sizeof(server_address));
    		server_address.sin_family = AF_INET;
    		server_address.sin_port = htons(gobal_config.port);
    		server_address.sin_addr.s_addr = inet_addr(gobal_config.server);

    		if(bind(broadcast_socket, (struct sockaddr*)&server_address, sizeof(server_address)) < 0)
    		{
        		FATAL("***Cannot bind the socket with the address! %s(%d)***", strerror(errno), errno);
        		goto ERROR;
    		}

			char buffer[DHCP_MAX_MTU];
			int length = serialize(response, buffer, DHCP_MAX_MTU);
			
			struct sockaddr_in broadcast = {0};
			broadcast.sin_family = AF_INET;
			broadcast.sin_port = htons(BOOTP_REPLAY_PORT);
			broadcast.sin_addr.s_addr = htonl(INADDR_BROADCAST);

			int send_length = sendto(broadcast_socket, buffer, length, 0, (struct sockaddr*)&broadcast, sizeof(broadcast));
			if(send_length < 0)
			{
				WARN("***Send data error! %s(%d)***", strerror(errno), errno);
			}
			else
			{
				DEBUG("Total %d bytes send!", send_length);
			}
ERROR:
			if(0 != broadcast_socket)
			{
				close(broadcast_socket);
			}
			free_packet(response);
		}
		else
		{
			WARN("Response packet is NULL.");
		}
		
		free_packet(request);
	}
	else
	{
		WARN("Can not marshall request packet from raw bytes.");
	}
	free(msg);
	
	INFO("handle_msg==>");
	return NULL;
}

struct dhcp_packet *dispatch(struct dhcp_packet *request)
{	
	INFO("==>dispatch");
	if(NULL == request)
	{
		ERROR("***Request packet is NULL***");
		goto ERROR;
	}

	if(BOOT_REQUEST != request->op)
	{
		WARN("***Packet is not send from dhcp client, ignor!***");
		goto ERROR;
	}

	//get the dhcp packet type
	char type = '\0';
	struct dhcp_option *option = request->options;
	while(NULL != option)
	{
		if(DHO_DHCP_MESSAGE_TYPE == option->code)
		{
			type = *option->value;
			break;
		}
		
		option = option->next;
	}

	if('\0' == type)
	{
		ERROR("***No dhcp message type found in the packet!***");
		goto ERROR;
	}
	DEBUG("packet type=%d", type);
	struct dhcp_packet *response = NULL;
	switch(type)
	{
		case DHCP_DISCOVER:
			response = gobal_packet_handler.do_discover(request);
			break;
		case DHCP_RELEASE:
			response = gobal_packet_handler.do_release(request);
			break;
		case DHCP_INFORM:
			response = gobal_packet_handler.do_inform(request);
			break;
		case DHCP_REQUEST:
			response = gobal_packet_handler.do_request(request);
			break;
		case DHCP_DECLINE:
			response = gobal_packet_handler.do_decline(request);
			break;
		default:
			break;
	}
	
	INFO("dispatch==>");
	return response;
ERROR:
	INFO("***Error***, dispatch==>");
	return NULL;
}

extern ip_allocator ip_allocator_handler;

struct dhcp_packet *do_discover(struct dhcp_packet *request)
{
	INFO("==>do_discover");
	struct network_config config = {0};
	memcpy(config.hardware_address, request->chaddr, 16);
	
	if(ip_allocator_handler(&config) < 0)
	{
		WARN("Cannot assign IP address! do_discover==>");
		return NULL;
	}

	struct dhcp_packet *response = (struct dhcp_packet*)malloc(sizeof(struct dhcp_packet));
	if(NULL == response)
	{
		FATAL("***Allocate memory failed! %s(%d)*** do_discover==>", strerror(errno), errno);
		return NULL;
	}
	memset(response, 0, sizeof(struct dhcp_packet));

	response->op = BOOT_REPLY;
	response->htype = request->htype;
	response->hlen = request->hlen;
	response->hops = 1;
	memcpy(response->xid, request->xid, 4);
	memcpy(response->yiaddr, config.ip_address, 4);
	memcpy(response->flags, request->flags, 2);
	memcpy(response->chaddr, request->chaddr, 16);
	
	//options
	//message type
	struct dhcp_option *packet_type = (struct dhcp_option*)malloc(sizeof(struct dhcp_option));
	if(NULL == packet_type)
	{
		free_packet(response);
		FATAL("***Allocate memory failed! %s(%d)*** do_discover==>", strerror(errno), errno);
		return NULL;
	}
	memset(packet_type, 0, sizeof(struct dhcp_option));
	packet_type->code = DHO_DHCP_MESSAGE_TYPE;
	packet_type->value = (char *)malloc(1);
	if(NULL == packet_type->value)
	{
		free_packet(response);
		FATAL("***Allocate memory failed! %s(%d)*** do_discover==>", strerror(errno), errno);
		return NULL;
	}
	*packet_type->value = DHCP_OFFER;
	packet_type->length = 1;
	response->options = packet_type;

	//server identifier
	struct dhcp_option *server_identifier = (struct dhcp_option*)malloc(sizeof(struct dhcp_option));
	if(NULL == server_identifier)
	{
		free_packet(response);
		FATAL("***Allocate memory failed! %s(%d)*** do_discover==>", strerror(errno), errno);
		return NULL;
	}
    memset(server_identifier, 0, sizeof(struct dhcp_option));
    server_identifier->code = DHO_DHCP_SERVER_IDENTIFIER;
    server_identifier->value = (char *)malloc(4);
	if(NULL == server_identifier->value)
	{
		free_packet(response);
		FATAL("***Allocate memory failed! %s(%d)*** do_discover==>", strerror(errno), errno);
		return NULL;
	}
	ip_asc2bytes(server_identifier->value, gobal_config.server);
    server_identifier->length = 4;
    packet_type->next = server_identifier;

	//lease time
	struct dhcp_option *lease_time = (struct dhcp_option*)malloc(sizeof(struct dhcp_option));
	if(NULL == lease_time)
	{
		free_packet(response);
		FATAL("***Allocate memory failed! %s(%d)*** do_discover==>", strerror(errno), errno);
		return NULL;
	}
    memset(lease_time, 0, sizeof(struct dhcp_option));
    lease_time->code = DHO_DHCP_LEASE_TIME;
    lease_time->value = (char *)malloc(4);
	if(NULL == lease_time->value)
	{
		free_packet(response);
		FATAL("***Allocate memory failed! %s(%d)*** do_discover==>", strerror(errno), errno);
		return NULL;
	}
    memcpy(lease_time->value, &gobal_config.lease, 4);
    lease_time->length = 4;
    server_identifier->next = lease_time;

	//renew time
	struct dhcp_option *renew_time = (struct dhcp_option*)malloc(sizeof(struct dhcp_option));
	if(NULL == renew_time)
	{
		free_packet(response);
		FATAL("***Allocate memory failed! %s(%d)*** do_discover==>", strerror(errno), errno);
		return NULL;
	}
    memset(renew_time, 0, sizeof(struct dhcp_option));
    renew_time->code = DHO_DHCP_RENEWAL_TIME;
    renew_time->value = (char *)malloc(4);
	if(NULL == renew_time->value)
	{
		free_packet(response);
		FATAL("***Allocate memory failed! %s(%d)*** do_discover==>", strerror(errno), errno);
		return NULL;
	}
    memcpy(renew_time->value, &gobal_config.renew, 4);
    renew_time->length = 4;
    lease_time->next = renew_time;

	//router/gateway
	struct dhcp_option *router = (struct dhcp_option*)malloc(sizeof(struct dhcp_option));
	if(NULL == router)
	{
		free_packet(response);
		FATAL("***Allocate memory failed! %s(%d)*** do_discover==>", strerror(errno), errno);
		return NULL;
	}
    memset(router, 0, sizeof(struct dhcp_option));
    router->code = DHO_ROUTERS;
    router->value = (char *)malloc(4);
	if(NULL == router->value)
	{
		free_packet(response);
		FATAL("***Allocate memory failed! %s(%d)*** do_discover==>", strerror(errno), errno);
		return NULL;
	}
    memcpy(router->value, config.router, 4);
    router->length = 4;
    renew_time->next = router;

	//netmask
	struct dhcp_option *subnet_mask = (struct dhcp_option*)malloc(sizeof(struct dhcp_option));
	if(NULL == subnet_mask)
	{
		free_packet(response);
		FATAL("***Allocate memory failed! %s(%d)*** do_discover==>", strerror(errno), errno);
		return NULL;
	}
    memset(subnet_mask, 0, sizeof(struct dhcp_option));
    subnet_mask->code = DHO_SUBNET;
    subnet_mask->value = (char *)malloc(4);
	if(NULL == subnet_mask->value)
	{
		free_packet(response);
		FATAL("***Allocate memory failed! %s(%d)*** do_discover==>", strerror(errno), errno);
		return NULL;
	}
    memcpy(subnet_mask->value, config.netmask, 4);
    subnet_mask->length = 4;
    router->next = subnet_mask;

	//dns
	struct dhcp_option *dns_server = (struct dhcp_option*)malloc(sizeof(struct dhcp_option));
	if(NULL == dns_server)
	{
		free_packet(response);
		FATAL("***Allocate memory failed! %s(%d)*** do_discover==>", strerror(errno), errno);
		return NULL;
	}
    memset(dns_server, 0, sizeof(struct dhcp_option));
    dns_server->code = DHO_DOMAIN_NAME_SERVERS;
    dns_server->value = (char *)malloc(8);
	if(NULL == dns_server->value)
	{
		free_packet(response);
		FATAL("***Allocate memory failed! %s(%d)*** do_discover==>", strerror(errno), errno);
		return NULL;
	}
    memcpy(dns_server->value, config.dns1, 4);
	memcpy(dns_server->value + 4, config.dns2, 4);
    dns_server->length = 8;
    subnet_mask->next = dns_server;
	
	INFO("do_discover==>");
	return response;
}

struct dhcp_packet *do_request(struct dhcp_packet *request)
{
	INFO("==>do_request");
	struct network_config config = {0};
	memcpy(config.hardware_address, request->chaddr, 16);
	
	if(ip_allocator_handler(&config) < 0)
	{
		WARN("Cannot assign IP address! do_request==>");
		return NULL;
	}
	
	char type = DHCP_ACK;
	char requested_address[4] = {0};
	
	if(0 != memcmp(requested_address, request->ciaddr, 4))
	{
		INFO("request->ciaddr is not 0, copy it to request_address");
		memcpy(requested_address, request->ciaddr, 4);
	}
	else
	{
		INFO("request->ciaddr is 0, get request_address from dhcp option");
		struct dhcp_option *option = request->options;
		while(NULL != option)
		{
			if(DHO_DHCP_REQUESTED_ADDRESS == option->code && option->length >= 4)
			{
				memcpy(requested_address, option->value, 4);
				break;
			}
			
			option = option->next;
		}
	}
	
	if(0 != memcmp(config.ip_address, requested_address, 4))
	{
		WARN("request_address is not the same as IP assigned, change packet type to NAK");
		type = DHCP_NAK;
	}
	
	struct dhcp_packet *response = (struct dhcp_packet*)malloc(sizeof(struct dhcp_packet));
	memset(response, 0, sizeof(struct dhcp_packet));

	response->op = BOOT_REPLY;
	response->htype = request->htype;
	response->hlen = request->hlen;
	response->hops = 1;
	memcpy(response->xid, request->xid, 4);
	memcpy(response->yiaddr, requested_address, 4);
	memcpy(response->flags, request->flags, 2);
	memcpy(response->chaddr, request->chaddr, 16);
	
	if(DHCP_ACK == type)
	{
		//options
		//message type
		struct dhcp_option *packet_type = (struct dhcp_option*)malloc(sizeof(struct dhcp_option));
		if(NULL == packet_type)
		{
			free_packet(response);
			FATAL("***Allocate memory failed! %s(%d)*** do_discover==>", strerror(errno), errno);
			return NULL;
		}
		memset(packet_type, 0, sizeof(struct dhcp_option));
		packet_type->code = DHO_DHCP_MESSAGE_TYPE;
		packet_type->value = (char *)malloc(1);
		if(NULL == packet_type->value)
		{
			free_packet(response);
			FATAL("***Allocate memory failed! %s(%d)*** do_discover==>", strerror(errno), errno);
			return NULL;
		}
		*packet_type->value = type;
		packet_type->length = 1;
		response->options = packet_type;

		//server identifier
		struct dhcp_option *server_identifier = (struct dhcp_option*)malloc(sizeof(struct dhcp_option));
		if(NULL == server_identifier)
		{
			free_packet(response);
			FATAL("***Allocate memory failed! %s(%d)*** do_discover==>", strerror(errno), errno);
			return NULL;
		}
		memset(server_identifier, 0, sizeof(struct dhcp_option));
		server_identifier->code = DHO_DHCP_SERVER_IDENTIFIER;
		server_identifier->value = (char *)malloc(4);
		if(NULL == server_identifier->value)
		{
			free_packet(response);
			FATAL("***Allocate memory failed! %s(%d)*** do_discover==>", strerror(errno), errno);
			return NULL;
		}
		ip_asc2bytes(server_identifier->value, gobal_config.server);
		server_identifier->length = 4;
		packet_type->next = server_identifier;

		//lease time
		struct dhcp_option *lease_time = (struct dhcp_option*)malloc(sizeof(struct dhcp_option));
		if(NULL == lease_time)
		{
			free_packet(response);
			FATAL("***Allocate memory failed! %s(%d)*** do_discover==>", strerror(errno), errno);
			return NULL;
		}
		memset(lease_time, 0, sizeof(struct dhcp_option));
		lease_time->code = DHO_DHCP_LEASE_TIME;
		lease_time->value = (char *)malloc(4);
		if(NULL == lease_time->value)
		{
			free_packet(response);
			FATAL("***Allocate memory failed! %s(%d)*** do_discover==>", strerror(errno), errno);
			return NULL;
		}
		memcpy(lease_time->value, &gobal_config.lease, 4);
		lease_time->length = 4;
		server_identifier->next = lease_time;

		//renew time
		struct dhcp_option *renew_time = (struct dhcp_option*)malloc(sizeof(struct dhcp_option));
		if(NULL == renew_time)
		{
			free_packet(response);
			FATAL("***Allocate memory failed! %s(%d)*** do_discover==>", strerror(errno), errno);
			return NULL;
		}
		memset(renew_time, 0, sizeof(struct dhcp_option));
		renew_time->code = DHO_DHCP_RENEWAL_TIME;
		renew_time->value = (char *)malloc(4);
		if(NULL == renew_time->value)
		{
			free_packet(response);
			FATAL("***Allocate memory failed! %s(%d)*** do_discover==>", strerror(errno), errno);
			return NULL;
		}
		memcpy(renew_time->value, &gobal_config.renew, 4);
		renew_time->length = 4;
		lease_time->next = renew_time;

		//router/gateway
		struct dhcp_option *router = (struct dhcp_option*)malloc(sizeof(struct dhcp_option));
		if(NULL == router)
		{
			free_packet(response);
			FATAL("***Allocate memory failed! %s(%d)*** do_discover==>", strerror(errno), errno);
			return NULL;
		}
		memset(router, 0, sizeof(struct dhcp_option));
		router->code = DHO_ROUTERS;
		router->value = (char *)malloc(4);
		if(NULL == router->value)
		{
			free_packet(response);
			FATAL("***Allocate memory failed! %s(%d)*** do_discover==>", strerror(errno), errno);
			return NULL;
		}
		memcpy(router->value, config.router, 4);
		router->length = 4;
		renew_time->next = router;

		//netmask
		struct dhcp_option *subnet_mask = (struct dhcp_option*)malloc(sizeof(struct dhcp_option));
		if(NULL == subnet_mask)
		{
			free_packet(response);
			FATAL("***Allocate memory failed! %s(%d)*** do_discover==>", strerror(errno), errno);
			return NULL;
		}
		memset(subnet_mask, 0, sizeof(struct dhcp_option));
		subnet_mask->code = DHO_SUBNET;
		subnet_mask->value = (char *)malloc(4);
		if(NULL == subnet_mask->value)
		{
			free_packet(response);
			FATAL("***Allocate memory failed! %s(%d)*** do_discover==>", strerror(errno), errno);
			return NULL;
		}
		memcpy(subnet_mask->value, config.netmask, 4);
		subnet_mask->length = 4;
		router->next = subnet_mask;

		//dns
		struct dhcp_option *dns_server = (struct dhcp_option*)malloc(sizeof(struct dhcp_option));
		if(NULL == dns_server)
		{
			free_packet(response);
			FATAL("***Allocate memory failed! %s(%d)*** do_discover==>", strerror(errno), errno);
			return NULL;
		}
		memset(dns_server, 0, sizeof(struct dhcp_option));
		dns_server->code = DHO_DOMAIN_NAME_SERVERS;
		dns_server->value = (char *)malloc(8);
		if(NULL == dns_server->value)
		{
			free_packet(response);
			FATAL("***Allocate memory failed! %s(%d)*** do_discover==>", strerror(errno), errno);
			return NULL;
		}
		memcpy(dns_server->value, config.dns1, 4);
		memcpy(dns_server->value + 4, config.dns2, 4);
		dns_server->length = 8;
		subnet_mask->next = dns_server;
	}
	
	INFO("do_request==>");
	return response;
}

struct dhcp_packet *do_release(struct dhcp_packet *request)
{
	INFO("==>do_release");
	return NULL;
	INFO("do_release==>");
}

struct dhcp_packet *do_inform(struct dhcp_packet *request)
{
	INFO("==>do_inform");
    struct network_config config = {0};
	memcpy(config.hardware_address, request->chaddr, 16);
	
	if(ip_allocator_handler(&config) < 0)
	{
		WARN("Cannot assign IP address! do_inform==>");
		return NULL;
	}

	struct dhcp_packet *response = (struct dhcp_packet*)malloc(sizeof(struct dhcp_packet));
	memset(response, 0, sizeof(struct dhcp_packet));

	response->op = BOOT_REPLY;
	response->htype = request->htype;
	response->hlen = request->hlen;
	response->hops = 1;
	memcpy(response->xid, request->xid, 4);
	memcpy(response->yiaddr, config.ip_address, 4);
	memcpy(response->flags, request->flags, 2);
	memcpy(response->chaddr, request->chaddr, 16);
	
	//options
	//message type
	struct dhcp_option *packet_type = (struct dhcp_option*)malloc(sizeof(struct dhcp_option));
	if(NULL == packet_type)
	{
		free_packet(response);
		FATAL("***Allocate memory failed! %s(%d)*** do_discover==>", strerror(errno), errno);
		return NULL;
	}
	memset(packet_type, 0, sizeof(struct dhcp_option));
	packet_type->code = DHO_DHCP_MESSAGE_TYPE;
	packet_type->value = (char *)malloc(1);
	if(NULL == packet_type->value)
	{
		free_packet(response);
		FATAL("***Allocate memory failed! %s(%d)*** do_discover==>", strerror(errno), errno);
		return NULL;
	}
	*packet_type->value = DHCP_ACK;
	packet_type->length = 1;
	response->options = packet_type;

	//server identifier
	struct dhcp_option *server_identifier = (struct dhcp_option*)malloc(sizeof(struct dhcp_option));
	if(NULL == server_identifier)
	{
		free_packet(response);
		FATAL("***Allocate memory failed! %s(%d)*** do_discover==>", strerror(errno), errno);
		return NULL;
	}
    memset(server_identifier, 0, sizeof(struct dhcp_option));
    server_identifier->code = DHO_DHCP_SERVER_IDENTIFIER;
    server_identifier->value = (char *)malloc(4);
	if(NULL == server_identifier->value)
	{
		free_packet(response);
		FATAL("***Allocate memory failed! %s(%d)*** do_discover==>", strerror(errno), errno);
		return NULL;
	}
	ip_asc2bytes(server_identifier->value, gobal_config.server);
    server_identifier->length = 4;
    packet_type->next = server_identifier;

	//lease time
	struct dhcp_option *lease_time = (struct dhcp_option*)malloc(sizeof(struct dhcp_option));
	if(NULL == lease_time)
	{
		free_packet(response);
		FATAL("***Allocate memory failed! %s(%d)*** do_discover==>", strerror(errno), errno);
		return NULL;
	}
    memset(lease_time, 0, sizeof(struct dhcp_option));
    lease_time->code = DHO_DHCP_LEASE_TIME;
    lease_time->value = (char *)malloc(4);
	if(NULL == lease_time->value)
	{
		free_packet(response);
		FATAL("***Allocate memory failed! %s(%d)*** do_discover==>", strerror(errno), errno);
		return NULL;
	}
    memcpy(lease_time->value, &gobal_config.lease, 4);
    lease_time->length = 4;
    server_identifier->next = lease_time;

	//renew time
	struct dhcp_option *renew_time = (struct dhcp_option*)malloc(sizeof(struct dhcp_option));
	if(NULL == renew_time)
	{
		free_packet(response);
		FATAL("***Allocate memory failed! %s(%d)*** do_discover==>", strerror(errno), errno);
		return NULL;
	}
    memset(renew_time, 0, sizeof(struct dhcp_option));
    renew_time->code = DHO_DHCP_RENEWAL_TIME;
    renew_time->value = (char *)malloc(4);
	if(NULL == renew_time->value)
	{
		free_packet(response);
		FATAL("***Allocate memory failed! %s(%d)*** do_discover==>", strerror(errno), errno);
		return NULL;
	}
    memcpy(renew_time->value, &gobal_config.renew, 4);
    renew_time->length = 4;
    lease_time->next = renew_time;

	//router/gateway
	struct dhcp_option *router = (struct dhcp_option*)malloc(sizeof(struct dhcp_option));
	if(NULL == router)
	{
		free_packet(response);
		FATAL("***Allocate memory failed! %s(%d)*** do_discover==>", strerror(errno), errno);
		return NULL;
	}
    memset(router, 0, sizeof(struct dhcp_option));
    router->code = DHO_ROUTERS;
    router->value = (char *)malloc(4);
	if(NULL == router->value)
	{
		free_packet(response);
		FATAL("***Allocate memory failed! %s(%d)*** do_discover==>", strerror(errno), errno);
		return NULL;
	}
    memcpy(router->value, config.router, 4);
    router->length = 4;
    renew_time->next = router;

	//netmask
	struct dhcp_option *subnet_mask = (struct dhcp_option*)malloc(sizeof(struct dhcp_option));
	if(NULL == subnet_mask)
	{
		free_packet(response);
		FATAL("***Allocate memory failed! %s(%d)*** do_discover==>", strerror(errno), errno);
		return NULL;
	}
    memset(subnet_mask, 0, sizeof(struct dhcp_option));
    subnet_mask->code = DHO_SUBNET;
    subnet_mask->value = (char *)malloc(4);
	if(NULL == subnet_mask->value)
	{
		free_packet(response);
		FATAL("***Allocate memory failed! %s(%d)*** do_discover==>", strerror(errno), errno);
		return NULL;
	}
    memcpy(subnet_mask->value, config.netmask, 4);
    subnet_mask->length = 4;
    router->next = subnet_mask;

	//dns
	struct dhcp_option *dns_server = (struct dhcp_option*)malloc(sizeof(struct dhcp_option));
	if(NULL == dns_server)
	{
		free_packet(response);
		FATAL("***Allocate memory failed! %s(%d)*** do_discover==>", strerror(errno), errno);
		return NULL;
	}
    memset(dns_server, 0, sizeof(struct dhcp_option));
    dns_server->code = DHO_DOMAIN_NAME_SERVERS;
    dns_server->value = (char *)malloc(8);
	if(NULL == dns_server->value)
	{
		free_packet(response);
		FATAL("***Allocate memory failed! %s(%d)*** do_discover==>", strerror(errno), errno);
		return NULL;
	}
    memcpy(dns_server->value, config.dns1, 4);
	memcpy(dns_server->value + 4, config.dns2, 4);
    dns_server->length = 8;
    subnet_mask->next = dns_server;
	
	INFO("do_inform==>");
	return response;
}

struct dhcp_packet *do_decline(struct dhcp_packet *request)
{
	INFO("==>do_decline");
    return NULL;
	INFO("do_decline==>");
}

int main()
{
	log_init("/source/dhcp/dhcp_log.conf");
	start_server("/source/dhcp/dhcp_server.conf");
}
