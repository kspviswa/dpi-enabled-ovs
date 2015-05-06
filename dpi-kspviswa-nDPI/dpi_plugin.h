/*
 * dpi_plugin.h
 *
 *  Created on: 04-Apr-2015
 *      Author: kspviswa
 */

#ifndef DPI_PLUGIN_H_
#define DPI_PLUGIN_H_

typedef signed long int32;
typedef unsigned long uint32;

enum DPILOGLEVEL
{
	DPIERR=1,
	DPIINFO,
	DPIWARN,
	DPIDEBUG,
	DPIMAX
};

int32 engine_init();
int32 engine_destroy();
int32 engine_process(void *packet, uint32 nSize);
extern void DpiWriteLog(int nlevel, char *format, ...);

#endif /* DPI_PLUGIN_H_ */
