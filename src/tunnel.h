#ifndef _TUNNEL_H_INCLUDED_
#define _TUNNEL_H_INCLUDED_

int tunnel_add(const char *interface,
		const char *name,
		unsigned long saddr);

int tunnel_up(const char *name);

int tunnel_down(const char *name);

int tunnel_del(const char *name);

unsigned long get_if_addr(const char *dev);







#endif
