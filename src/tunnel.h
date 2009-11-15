#ifndef _TUNNEL_H_INCLUDED_
#define _TUNNEL_H_INCLUDED_

#include <stdint.h>

uint32_t get_if_addr(const char *dev);

int tunnel_add(const char *dev,
		const char *link,
		uint32_t saddr,
		uint8_t ttl,
		int pmtudisc);

int tunnel_up(const char *dev);

int tunnel_down(const char *dev);

int tunnel_del(const char *dev);

int tunnel_set_mtu(const char *dev, int mtu);

int tunnel_add_prl(const char *dev,
		uint32_t addr,
		int default_rtr);

int tunnel_del_prl(const char *dev, uint32_t addr);


#endif
