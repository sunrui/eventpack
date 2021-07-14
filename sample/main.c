#include <pthread.h>

#include <sys/time.h>
#include <unistd.h>
#include <stdio.h>

#include "ep_alloctor.h"
#include "ep_util.h"

#ifdef WIN32
//#include "vld.h"
#endif

void client_main();
void server_main();

void * service_proc(void * param)
{
	server_main();

	return NULL;
}

void * client_proc(void * param)
{
	client_main();

	return NULL;
}

extern void do_testcase();

void do_rpc()
{
	pthread_t tid;
	int cnt;

	pthread_create(&tid, 0, service_proc, NULL);
	usleep(500 * 1000);
	
	for (cnt = 0; cnt < 2000; cnt++)
	{
		pthread_t ctid;

		pthread_create(&ctid, 0, client_proc, NULL);
		pthread_detach(ctid);

		usleep(50 * 1000);
	}

	pthread_join(tid, NULL);

#ifdef WIN32
	pthread_win32_thread_detach_np();
	pthread_win32_process_detach_np();
#endif
}

int main()
{
#ifdef WIN32
	ep_sock_win32_init(1);
	pthread_win32_process_attach_np();
#endif
	//do_testcase();
	do_rpc();

	return 0;
}
