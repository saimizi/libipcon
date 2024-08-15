#include "ut.h"
extern int ipcon_create_handler_run(void *);

int main(void)
{
	int ret = 0;

	ret = (ret == 0) ? ipcon_create_handler_run(NULL) : ret;

	return ret;
}
