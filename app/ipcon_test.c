#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>


#define ipcon_debug(fmt, ...)	printf("[ipcon] "fmt, ##__VA_ARGS__)
#define ipcon_info(fmt, ...)	printf("[ipcon] "fmt, ##__VA_ARGS__)
#define ipcon_err(fmt, ...)	printf("[ipcon] "fmt, ##__VA_ARGS__)


int main(int argc, char *argv[])
{
	return 0;
}
