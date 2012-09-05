#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<errno.h>

#include "dhcp_packet.h"
#include "dhcp_log.h"

char DHCP_MAGIC_COOKIE[4] = {0x63, 0x82, 0x53, 0x63};

//Caller need to free the memory used for the DHCP packet 
struct dhcp_packet *marshall(char buffer[], int offset, int length)
{
	INFO("==>marshall, offset=%d, length=%d", offset, length);
	
	struct dhcp_packet *packet = NULL;
	//first check if the arguments is valid
	if(NULL == buffer)
	{
		ERROR("***BUFFER for marshall is NULL***");
		goto ERROR;
	}
	
	if(length < BOOTP_ABSOLUTE_MIN_LEN)
	{
		ERROR("The length of dhcp packet is less than min size");
		goto ERROR;
	}

	if(length > DHCP_MAX_MTU)
	{
		ERROR("The length of dhcp packet is more than max MTU");
		goto ERROR;
	}

	packet = (struct dhcp_packet*)malloc(sizeof(struct dhcp_packet));
	if(NULL == packet)
	{
		FATAL("***Allocate memory failed! %s(%d)***", strerror(errno), errno);
		goto ERROR;
	}
	
	memset(packet, 0, sizeof(struct dhcp_packet));
	
	void* packet_begin = buffer + offset; 
	//parse static part of packet
	memcpy(&(packet->op), packet_begin, 1);
	memcpy(&(packet->htype), packet_begin + 1, 1);
	memcpy(&(packet->hlen), packet_begin + 2, 1);
	memcpy(&(packet->hops), packet_begin + offset + 3, 1);
	memcpy(packet->xid, packet_begin + 4, 4);
	memcpy(packet->secs, packet_begin + 8, 2);
	memcpy(packet->flags, packet_begin + 10, 2);
	memcpy(packet->ciaddr, packet_begin + 12, 4);
	memcpy(packet->yiaddr, packet_begin + 16, 4);
	memcpy(packet->siaddr, packet_begin + 20, 4);
	memcpy(packet->giaddr, packet_begin + 24, 4);
	memcpy(packet->chaddr, packet_begin + 28, 16);
	memcpy(packet->sname, packet_begin + 44, 64);
	memcpy(packet->file, packet_begin + 108, 128);
	
	DEBUG("--------------DUMP DHCP PACKET-------------");
	DEBUG("packet->op=%d", packet->op);
	DEBUG("packet->htype=%d", packet->htype);
	DEBUG("packet->hlen=%d", packet->hlen);
	DEBUG("packet->hops=%d", packet->hops);
	DEBUG("packet->xid=%x,%x,%x,%x", packet->xid[0], packet->xid[1], packet->xid[2], packet->xid[3]);
	DEBUG("packet->secs=%x,%x", packet->secs[0], packet->secs[1]);
	DEBUG("packet->flags=%x,%x", packet->flags[0], packet->flags[1]);
	DEBUG("packet->ciaddr=%x,%x,%x,%x", packet->ciaddr[0], packet->ciaddr[1], packet->ciaddr[2], packet->ciaddr[3]);
	DEBUG("packet->yiaddr=%x,%x,%x,%x", packet->yiaddr[0], packet->yiaddr[1], packet->yiaddr[2], packet->yiaddr[3]);
	DEBUG("packet->siaddr=%x,%x,%x,%x", packet->siaddr[0], packet->siaddr[1], packet->siaddr[2], packet->siaddr[3]);
	DEBUG("packet->giaddr=%x,%x,%x,%x", packet->giaddr[0], packet->giaddr[1], packet->giaddr[2], packet->giaddr[3]);
	DEBUG("packet->chaddr=%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x", packet->chaddr[0], packet->chaddr[1], packet->chaddr[2], 
	packet->chaddr[3], packet->chaddr[4], packet->chaddr[5], packet->chaddr[6], packet->chaddr[7], packet->chaddr[8], packet->chaddr[9], 
	packet->chaddr[10], packet->chaddr[11], packet->chaddr[12], packet->chaddr[13], packet->chaddr[14], packet->chaddr[15]);
	DEBUG("packet->sname=%s", packet->sname);
	DEBUG("packet->file=%s", packet->file);
	DEBUG("---------------------------------------------");
	
	//check DHCP magic cookie
	char magic[4];
	memcpy(magic, packet_begin + 236, 4);
	if(0 != memcmp(DHCP_MAGIC_COOKIE, magic, 4))
	{
		ERROR("DHCP packet magic cookie is not matched!");
		goto ERROR;
	}

	//parse options
	int options_offset = 240; //236 + 4
	packet->options = NULL;
	struct dhcp_option *prev = NULL;
	while(1)
	{ 
		if(options_offset > length - 1)
		{
			break;
		}
		
		//code
		char code;
		memcpy(&code, packet_begin + options_offset, 1);
		options_offset++;

		DEBUG("dhcp option code=%d", code);

		if(DHO_PAD == code)
		{
			continue;
		}
		
		if(DHO_END == code)
		{
			INFO("dhcp option end");
			break;
		}

		//length
		int len;
		char len_buff;
		memcpy(&len_buff, packet_begin + options_offset, 1);
		len = (int)len_buff;
		options_offset++;
		
		DEBUG("dhcp option length=%d", len);

		if(options_offset + len > length - 1)
		{
			WARN("The options length is more than packet length, but no end mark.");
			break;
		}
		
		//value
		struct dhcp_option * option = (struct dhcp_option*)malloc(sizeof(struct dhcp_option));
		if(NULL == option)
		{
			FATAL("***Allocate memory failed! %s(%d)***", strerror(errno), errno);
			goto ERROR;
		}
		memset(option, 0, sizeof(struct dhcp_option));

		option->code = code;
		option->length = len_buff;
		option->value = (char*)malloc(len);
		if(NULL == option->value)
		{
			FATAL("***Allocate memory failed! %s(%d)***", strerror(errno), errno);
			goto ERROR;
		}
		memcpy(option->value, buffer + options_offset, len);
		option->next = NULL;	
		options_offset += len;
		
		//Add the option into the packet
		if(NULL == packet->options)
		{
			packet->options = option;
		}	
		if(NULL != prev)
		{
			prev->next = option;
		}
		
		prev = option;
	}

	if(options_offset < length - 1)
	{
		packet->padding = (char*)malloc(length - options_offset);
		if(NULL == packet->padding)
		{
			FATAL("***Allocate memory failed! %s(%d)***", strerror(errno), errno);
		}
		else
		{
			memcpy(packet->padding, buffer + options_offset, length - options_offset - 1);
		}
	}
	else
	{
		packet->padding = NULL;
	}
	
	INFO("marshall==>");
	return packet;

ERROR:
	if(NULL != packet)
	{
		free_packet(packet);
	}
	WARN("***error!*** marshall==>");
	return NULL;
}

//Use this function to free dhcp packet
void free_packet(struct dhcp_packet *packet)
{
	INFO("==>free_packet, packet=%d", packet);
	if(NULL == packet)
	{
		INFO("packet pointer is NULL, free_packet==>");
		return;
	}

	if(NULL != packet->padding)
	{
		free(packet->padding);
	}

	struct dhcp_option *option = packet->options;
	while(NULL == option)
	{
		if(NULL != option->value)
		{
			free(option->value);
		}
		struct dhcp_option *current = option; 
		option = current->next;
		
		free(current);
	}

	free(packet);
	
	INFO("free_packet==>");
	return;
}

int serialize(struct dhcp_packet *packet, char buffer[], int length)
{
	INFO("serialize==>, packet=%d", packet);
	if(NULL == packet)
	{
		INFO("packet pointer is NULL, ==>serialize");
		return 0;
	}

	//calculate the total size of the packet
	//static part
	int packet_len = BOOTP_ABSOLUTE_MIN_LEN;
	//magic cookie
	packet_len += sizeof(DHCP_MAGIC_COOKIE);
	//options
	struct dhcp_option *option = packet->options;
	while(NULL != option)
	{
		packet_len += 2;
		packet_len += (int)option->length;
		option = option->next;
	}
	//end option
	packet_len++;
	
	//calculate padding length
	int padding_len = 0;
	if(packet_len < BOOTP_ABSOLUTE_MIN_LEN + DHCP_VEND_SIZE)
	{
		padding_len = DHCP_VEND_SIZE + BOOTP_ABSOLUTE_MIN_LEN - packet_len;
		packet_len = DHCP_VEND_SIZE + BOOTP_ABSOLUTE_MIN_LEN;
	}
	
	if(packet_len > length)
	{
		ERROR("Buffer size is less than packet length, buffer size=%d, packet length=%d", sizeof(buffer), packet_len);
		INFO("==>serialize");
		return 0;
	}
	
	DEBUG("--------------DUMP DHCP PACKET-------------");
	DEBUG("packet->op=%d", packet->op);
	DEBUG("packet->htype=%d", packet->htype);
	DEBUG("packet->hlen=%d", packet->hlen);
	DEBUG("packet->hops=%d", packet->hops);
	DEBUG("packet->xid=%x,%x,%x,%x", packet->xid[0], packet->xid[1], packet->xid[2], packet->xid[3]);
	DEBUG("packet->secs=%x,%x", packet->secs[0], packet->secs[1]);
	DEBUG("packet->flags=%x,%x", packet->flags[0], packet->flags[1]);
	DEBUG("packet->ciaddr=%x,%x,%x,%x", packet->ciaddr[0], packet->ciaddr[1], packet->ciaddr[2], packet->ciaddr[3]);
	DEBUG("packet->yiaddr=%x,%x,%x,%x", packet->yiaddr[0], packet->yiaddr[1], packet->yiaddr[2], packet->yiaddr[3]);
	DEBUG("packet->siaddr=%x,%x,%x,%x", packet->siaddr[0], packet->siaddr[1], packet->siaddr[2], packet->siaddr[3]);
	DEBUG("packet->giaddr=%x,%x,%x,%x", packet->giaddr[0], packet->giaddr[1], packet->giaddr[2], packet->giaddr[3]);
	DEBUG("packet->chaddr=%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x", packet->chaddr[0], packet->chaddr[1], packet->chaddr[2], 
	packet->chaddr[3], packet->chaddr[4], packet->chaddr[5], packet->chaddr[6], packet->chaddr[7], packet->chaddr[8], packet->chaddr[9], 
	packet->chaddr[10], packet->chaddr[11], packet->chaddr[12], packet->chaddr[13], packet->chaddr[14], packet->chaddr[15]);
	DEBUG("packet->sname=%s", packet->sname);
	DEBUG("packet->file=%s", packet->file);
	DEBUG("---------------------------------------------");
	
	memcpy(buffer, &(packet->op), 1);
	memcpy(buffer + 1, &(packet->htype), 1);
	memcpy(buffer + 2, &(packet->hlen), 1);
	memcpy(buffer + 3, &(packet->hops), 1);
	memcpy(buffer + 4, packet->xid, 4);
	memcpy(buffer + 8, packet->secs, 2);
	memcpy(buffer + 10, packet->flags, 2);
	memcpy(buffer + 12, packet->ciaddr, 4);
	memcpy(buffer + 16, packet->yiaddr, 4);
	memcpy(buffer + 20, packet->siaddr, 4);
	memcpy(buffer + 24, packet->giaddr, 4);
	memcpy(buffer + 28, packet->chaddr, 16);
	memcpy(buffer + 44, packet->sname, 64);
	memcpy(buffer + 108, packet->file, 128);

	memcpy(buffer + 236, DHCP_MAGIC_COOKIE, 4);
	
	int options_offset = 240;
	option = packet->options;
    while(NULL != option)
    {
		DEBUG("dhcp option code=%d, length=%d", option->code, option->length);
		memcpy(buffer + options_offset, &(option->code), 1);
		options_offset++;
		memcpy(buffer + options_offset, &(option->length), 1);
		options_offset++;

		int len = (int)option->length;
		memcpy(buffer + options_offset, option->value, len);
		options_offset += len;		

		option = option->next;
	}

	char dhcp_option_end = DHO_END;
	memcpy(buffer + options_offset, &dhcp_option_end, 1);
	options_offset++;	

	if(padding_len > 0)
	{
		memset(buffer + options_offset, 0, padding_len);  
	}

	INFO("total %d bytes writen, ==>serialize", packet_len);
	return packet_len; 
}
