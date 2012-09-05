#ifndef _LOG_H_
#define _LOG_H_

#define LOG_INFO	0
#define LOG_DEBUG	1
#define LOG_WARN	2
#define LOG_ERROR	3
#define LOG_FATAL	4

#define LOG_INFO_STRING		"INFO"
#define LOG_DEBUG_STRING	"DEBUG"
#define LOG_WARN_STRING		"WARN"
#define LOG_ERROR_STRING	"ERROR"
#define LOG_FATAL_STRING	"FATAL"

#define CONDIF_LOG_ENABLED		"log_enabled"
#define	CONFIG_LOG_LEVEL 		"log_level"
#define CONFIG_LOG_FILE_DIR 	"log_file"

#define CONFIG_BUFFER_SIZE	1024
#define LOG_BUFFER_SIZE		4096	//4KB
#define MAX_FILE_PATH		256

#define LOG_FILE_NAME_PREFIX	"dhcp_log"

struct log_config
{
	char log_enabled;
	char log_level;
	char log_file_dir[MAX_FILE_PATH];
};

int log_init(char *config_file);

void dhcp_log(char level, const char *source, const char *func, int line, char *message, ...);

char * log_level_string(char log_level);

#define INFO(message, ...)      dhcp_log(LOG_INFO, __FILE__, __FUNCTION__, __LINE__, message, ##__VA_ARGS__)
#define DEBUG(message, ...)     dhcp_log(LOG_DEBUG, __FILE__, __FUNCTION__, __LINE__, message, ##__VA_ARGS__)
#define WARN(message, ...)      dhcp_log(LOG_WARN, __FILE__, __FUNCTION__, __LINE__, message, ##__VA_ARGS__)
#define ERROR(message, ...)     dhcp_log(LOG_ERROR, __FILE__, __FUNCTION__, __LINE__, message, ##__VA_ARGS__)
#define FATAL(message, ...)     dhcp_log(LOG_FATAL, __FILE__, __FUNCTION__, __LINE__, message, ##__VA_ARGS__)


#endif
