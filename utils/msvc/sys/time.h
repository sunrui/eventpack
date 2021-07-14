/*
 * win32 posix time compatible
 *
 * @author rui.sun 2013-8-4 Sun 14:07
 */
#ifndef TIME_H
#define TIME_H

#ifdef _WIN32
#include <WinSock2.h>
#pragma comment(lib, "winmm.lib")

#define gettimeofday(tp, tzp) \
	do { \
		DWORD t; \
		t = timeGetTime(); \
		(tp)->tv_sec = t / 1000; \
		(tp)->tv_usec = t % 1000; \
	} while (0)

#define usleep(micro_seconds) \
	do { \
		Sleep(((micro_seconds) + 999) / 1000); \
	} while (0)

#define timerclear(tvp) (tvp)->tv_sec = (tvp)->tv_usec = 0
#define timerisset(tvp) ((tvp)->tv_sec || (tvp)->tv_usec)

#define timeradd(tvp, uvp, vvp) \
	do { \
		(vvp)->tv_sec = (tvp)->tv_sec + (uvp)->tv_sec; \
		(vvp)->tv_usec = (tvp)->tv_usec + (uvp)->tv_usec; \
		if ((vvp)->tv_usec >= 1000000) { \
			(vvp)->tv_sec++; \
			(vvp)->tv_usec -= 1000000; \
		} \
	} while (0)

#define timersub(tvp, uvp, vvp) \
	do { \
		(vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec; \
		(vvp)->tv_usec = (tvp)->tv_usec - (uvp)->tv_usec; \
		if ((vvp)->tv_usec < 0) { \
			(vvp)->tv_sec--; \
			(vvp)->tv_usec += 1000000; \
		} \
	} while (0)

#endif

#endif
