# Sample plugin based on OVS DPI interface

`dpi-interface.h` is the opaque interface, that has been added to OVS.

Any DPI plugin, which is adhering to `dpi-interface.h` can be plugged into OVS for DPI processing.

The sample plugin will demonstrate the DPI public API that was given for DPI-enabled-OVS.
This sample plugin will simply write out the ethernet packet from OVS to a file. Though there is anything special about logging ethernet packet to a file, it is important to note that, these ethernet packets are actually clones of incoming packets to the bridge inside OVS.

##Sample API usage

`// library init`
`
int32 dpiInit(const char* pszDpiLib, const char* szErrMsgBuf);
`

`// Process ethernet packet for DPI`
`
// DPI implementing library should convert the void *packet to ethernet packet
int32 dpiProcessPacket(void *packet, uint32 nSize);
`

`// library exit`
`
int32 dpiExit();
`

Logging API is also provided to log onto the OVS logfile, directly from dpi-plugin

`void DpiWriteLog(int nlevel, char *format, ...);`

Loglevels are `DPIERR` `DPIINFO` `DPIWARN` `DPIDEBUG`

