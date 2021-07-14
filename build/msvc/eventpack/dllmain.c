#include "ep_util.h"

#include <Windows.h>
#include <pthread.h>

//#include "vld.h"

/* Callback for our DLL so we can initialize pthread */
BOOL WINAPI DllMain(HANDLE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
#ifdef PTW32_STATIC_LIB
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		ep_sock_win32_init(1);
		pthread_win32_process_attach_np();
	case DLL_THREAD_ATTACH:
		pthread_win32_thread_attach_np();
		break;
	case DLL_THREAD_DETACH:
		pthread_win32_thread_detach_np();
		break;
	case DLL_PROCESS_DETACH:
		pthread_win32_process_detach_np();
		ep_sock_win32_init(0);
		break;
	}
#endif
	return TRUE;
}