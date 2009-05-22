#ifndef _TUNNEL_H_INCLUDED_
#define _TUNNEL_H_INCLUDED_

int tunnel_add(const char *dev,
		const char *link,
		uint32_t saddr);

int tunnel_up(const char *dev);

int tunnel_down(const char *dev);

int tunnel_del(const char *dev);

uint32_t get_if_addr(const char *dev);

#endif
