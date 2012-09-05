#include<stdio.h>
#include<string.h>
#include<sqlite3.h>

#include "dhcp_log.h"
#include "dhcp_server.h"

extern struct server_config gobal_config;

int sqlite_ip_allocator(struct network_config *config)
{
	INFO("==>sqlite_ip_allocate");
	sqlite3 *db = NULL;

	int ret = sqlite3_open(gobal_config.ip_allocator_file, &db);
	if(SQLITE_OK != ret)
        {
                ERROR("***sqlite3_open ERROR!!! %s(%d)***", sqlite3_errmsg(db), ret);
                goto ERROR;
        }

	sqlite3_stmt *statement = NULL;

	//get gateway, netmask, dns1 & dns2
	//create table network_config(
	//gateway text,
	//netmask text,
	//dns1 text,
	//dns2 text)
        ret = sqlite3_prepare(db, "select * from network_config", 128, &statement, NULL);

        if(SQLITE_OK != ret)
        {
                ERROR("***sqlite3_prepare ERROR!!! %s(%d)***", sqlite3_errmsg(db), ret);
                goto ERROR;
        }

        ret = sqlite3_step(statement);

        if(SQLITE_ROW != ret)
        {
                ERROR("***sqlite3_step ERROR!!! %s(%d)***", sqlite3_errmsg(db), ret);
                goto ERROR;
        }

	char asc_gateway[16] = {0};
	char asc_netmask[16] = {0};
	char asc_dns1[16] = {0};
	char asc_dns2[16] = {0};
	char asc_ip_address[16] = {0};

	const char *value = sqlite3_column_text(statement, 0);
	strncpy(asc_gateway, value, 16);
	value = sqlite3_column_text(statement, 1);
    strncpy(asc_netmask, value, 16);
	value = sqlite3_column_text(statement, 2);
    strncpy(asc_dns1, value, 16);
	value = sqlite3_column_text(statement, 3);
    strncpy(asc_dns2, value, 16);

	sqlite3_finalize(statement);

	DEBUG("gateway=%s, netmask=%s, dns1=%s, dns2=%s", asc_gateway, asc_netmask, asc_dns1, asc_dns2);
	
	//convert mac address to 64-bit int.
	//the first 6 bytes of network_config.hardware_address
	//should be mac address. 
	uint64_t mac = 0x0000000000000000;
	int i = 0;
	for(i = 0; i < 6; i++)
	{
		mac *= 0x100;
		DEBUG("mac=%lx", mac);
		mac += (uint8_t)config->hardware_address[i];
		DEBUG("mac=%lx", mac);
	}

	DEBUG("mac address=%02x:%02x:%02x:%02x:%02x:%02x, integer value=%ld", (uint8_t)config->hardware_address[0], (uint8_t)config->hardware_address[1], (uint8_t)config->hardware_address[2], (uint8_t)config->hardware_address[3], (uint8_t)config->hardware_address[4], (uint8_t)config->hardware_address[5], mac);
	char sql[128] = {0};
	snprintf(sql, 128, "select * from mac_ip where mac = %ld", mac);
	ret = sqlite3_prepare(db, sql, 128, &statement, NULL);

    if(SQLITE_OK != ret)
    {
    	ERROR("***sqlite3_prepare ERROR!!! %s(%d)***", sqlite3_errmsg(db), ret);
        goto ERROR;
    }
	
	ret = sqlite3_step(statement);

    if(SQLITE_ROW != ret)
    {
    	ERROR("***sqlite3_step ERROR!!! %s(%d)***", sqlite3_errmsg(db), ret);
        goto ERROR;
    }

	value = sqlite3_column_text(statement, 1);
    strncpy(asc_ip_address, value, 16);

	DEBUG("Allocate IP address: %s", asc_ip_address);
	sqlite3_finalize(statement);

    sqlite3_close(db);

	ip_asc2bytes(config->router, asc_gateway);
	ip_asc2bytes(config->netmask, asc_netmask);
	ip_asc2bytes(config->dns1, asc_dns1);
	ip_asc2bytes(config->dns2, asc_dns2);
	ip_asc2bytes(config->ip_address, asc_ip_address); 

	INFO("sqlite_ip_allocator==>");
	return 0;
ERROR:
	WARN("***ERROR sqlite_ip_allocator==>***");
	return -1;
}

ip_allocator ip_allocator_handler = &sqlite_ip_allocator;
