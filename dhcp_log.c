#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<stdarg.h>
#include<time.h>
#include<sys/types.h>

#include "dhcp_log.h"

struct log_config gobal_file_config = 
{
        .log_enabled = 0,
        .log_level = 3,
        .log_file_dir = "/var/log",
};

int log_init(char *config_file)
{
	//parse configuration file
	FILE *file = fopen(config_file, "r");
	if(NULL == file)
	{
		return -1;
	}
	char buffer[CONFIG_BUFFER_SIZE];

	while(!feof(file))
	{
		if(NULL != fgets(buffer, CONFIG_BUFFER_SIZE, file))
		{	
			int index = 0;
			for(; '\0' != buffer[index] && '=' != buffer[index]; index++);

			if('\0' == buffer[index])
			{
				continue;
			}
			
			buffer[index] = '\0';
			char *value_begin = buffer + index + 1;
			int value_length = strlen(value_begin);
			
			if(0 == strcmp(buffer, CONDIF_LOG_ENABLED))
			{
				memcpy(&gobal_file_config.log_enabled, value_begin, 1);
				gobal_file_config.log_enabled = gobal_file_config.log_enabled - '0';	
			}
			else if(0 == strcmp(buffer, CONFIG_LOG_LEVEL))
			{
				memcpy(&gobal_file_config.log_level, value_begin, 1);
				gobal_file_config.log_level = gobal_file_config.log_level - '0';
			}
			else if(0 == strcmp(buffer, CONFIG_LOG_FILE_DIR))
			{
				if('\n' == value_begin[value_length - 1])
				{
					value_begin[value_length - 1] = '\0';
				}

				strncpy(gobal_file_config.log_file_dir, value_begin , MAX_FILE_PATH);
				
			}
		}	
	}
	
	fclose(file);
}

void dhcp_log(char level, const char *source, const char *func, int line, char *message, ...)
{	
	if(0 == gobal_file_config.log_enabled || level < gobal_file_config.log_level)
	{
		return;
	}
	
	time_t now;
	time(&now);
	struct tm *tm_now = gmtime(&now); 
	char file_path[MAX_FILE_PATH] = {0};
	snprintf(file_path, MAX_FILE_PATH, "%s/%s_%4d-%02d-%02d.log", gobal_file_config.log_file_dir, LOG_FILE_NAME_PREFIX, tm_now->tm_year + 1900, tm_now->tm_mon + 1, tm_now->tm_mday);
	
	FILE *log_file = fopen(file_path, "a+");
	
	if(NULL == log_file)
	{
		return;
	}
	
	va_list arg_list;
	char buffer[LOG_BUFFER_SIZE];
	
	va_start(arg_list, message);
	vsnprintf(buffer, LOG_BUFFER_SIZE, message, arg_list);
	va_end(arg_list);

	fprintf(log_file, "%4d-%02d-%02d %02d:%02d:%02d  %s[%s][%d]\t%05d:%05d  %5s  %s\n", tm_now->tm_year + 1900, tm_now->tm_mon + 1, tm_now->tm_mday, tm_now->tm_hour, tm_now->tm_min, tm_now->tm_sec, source, func, line, getgid(), getpid(), log_level_string(level), buffer);
	
	fclose(log_file);
}

char * log_level_string(char log_level)
{
        switch(log_level)
        {
                case LOG_INFO:
                        return LOG_INFO_STRING;
                case LOG_DEBUG:
                        return LOG_DEBUG_STRING;
                case LOG_WARN:
                        return LOG_WARN_STRING;
                case LOG_ERROR:
                        return LOG_ERROR_STRING;
                case LOG_FATAL:
                        return LOG_FATAL_STRING;
                default:
                        break;
        }

        return NULL;
}

