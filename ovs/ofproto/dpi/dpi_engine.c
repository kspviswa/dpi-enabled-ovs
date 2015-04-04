/*
 * dpi-engine.c
 *
 *  Created on: 03-Apr-2015
 *      Author: kspviswa
 */



#include "dpi-interface.h"
#include <dlfcn.h>
#include <errno.h>
#include <stddef.h>

//Register this module
VLOG_DEFINE_THIS_MODULE(dpi_engine);

//Globals
void *dpiLib = NULL;
int32 (*engine_init)(void)  = NULL;
int32 (*engine_destroy)(void) = NULL;
int32 (*engine_process)(void*, uint32) = NULL;

void DpiWriteLog(int nlevel, char *format, ...)
{
	char buffer[256];
	va_list args;
	va_start (args, format);
	vsnprintf (buffer, 255, format, args);

	switch((enum DPILOGLEVEL)nlevel)
	{
	case DPIERR:
		VLOG_ERR(buffer);
		break;
	case DPIINFO:
		VLOG_INFO(buffer);
		break;
	case DPIDEBUG:
		VLOG_DBG(buffer);
		break;
	case DPIWARN:
		VLOG_WARN(buffer);
		break;
	default:
		break;
	}
	va_end(args);
}

int32 dpiInit(const char* pszDpiLib, const char* szErrMsgBuf)
{
	VLOG_DBG(__FUNCTION__);
	dpiLib = dlopen(pszDpiLib, RTLD_NOW|RTLD_GLOBAL);

	if(!dpiLib)
	{

		DpiWriteLog(DPIERR, "Fatal error. Unable to load %s", pszDpiLib);
		const char *szErr = dlerror();

		strncpy(szErrMsgBuf, szErr, strlen(szErr));

		return -1;
	}

	engine_init = dlsym(dpiLib, "engine_init");

	if(!engine_init)
	{
		const char *szErr = dlerror();
		strncpy(szErr, szErrMsgBuf, strlen(szErr));
		dlclose(dpiLib);
		return -1;
	}

	engine_destroy = dlsym(dpiLib, "engine_destroy");

	if(!engine_destroy)
	{
		const char *szErr = dlerror();
		strncpy(szErr, szErrMsgBuf, strlen(szErr));
		dlclose(dpiLib);
		return -1;
	}

	engine_process = dlsym(dpiLib, "engine_process");

	if(!engine_process)
	{
		const char *szErr = dlerror();
		strncpy(szErr, szErrMsgBuf, strlen(szErr));
		dlclose(dpiLib);
		return -1;
	}

	DpiWriteLog(DPIINFO, "Initializing the DPI engine");
	engine_init();

	return 0;
}

int32 dpiProcessPacket(void *packet, uint32 nSize)
{
	VLOG_DBG(__FUNCTION__);
	return engine_process(packet, nSize);
}

int32 dpiExit()
{
	VLOG_DBG(__FUNCTION__);
	int32 nResult = 0;

	nResult = engine_destroy();
	dlclose(dpiLib);

	DpiWriteLog(DPIINFO, "Quitting DPI engine");
	return nResult;
}
