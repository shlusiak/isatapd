/*
 * tunnel.c     lowlevel interface and tunnel routines
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Authors:     Sascha Hlusiak, <mail@saschahlusiak.de>
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <linux/if_tunnel.h>

#ifdef HAVE_CONFIG_H
	#include <config.h>
#endif

#include "tunnel.h"


/**
 * Return IPv4 address attached to interface 'dev' or 0 if error
 **/
uint32_t get_if_addr(const char *dev)
{
	struct ifreq ifr;
	int fd;

	if (dev == NULL)
		return 0;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, dev, IFNAMSIZ);

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return 0;

	if (ioctl(fd, SIOCGIFADDR, &ifr)) {
		close(fd);
		return 0;
	}
	close(fd);
	return ((struct sockaddr_in *)(&ifr.ifr_addr))->sin_addr.s_addr;
}

/**
 * Creates tunnel interface
 * Return -1 in case of error, otherwise 0
 **/
int tunnel_add(const char *dev,
		const char *link,
		uint32_t saddr,
		uint8_t ttl,
		int pmtudisc)
{
	struct ip_tunnel_parm p;
	struct ifreq ifr;
	int fd;

	memset(&p, 0, sizeof(p));

	p.iph.version = 4;
	p.iph.ihl = 5;
	p.iph.protocol = IPPROTO_IPV6;
	p.iph.saddr = saddr;
	p.iph.frag_off = pmtudisc ? htons(IP_DF) : 0;
	p.iph.ttl = ttl;

	p.i_flags |= SIT_ISATAP;
	strncpy(p.name, dev, IFNAMSIZ);
	if (link) {
		p.link = if_nametoindex(link);
		if (p.link <= 0)
			return -1;
	}

	strncpy(ifr.ifr_name, "sit0", IFNAMSIZ);
	ifr.ifr_ifru.ifru_data = (void*)&p;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		return -1;
	}
	if (ioctl(fd, SIOCADDTUNNEL, &ifr) < 0) {
		close(fd);
		return -1;
	}
	close(fd);

	return 0;
}

/**
 * Sets tunnel interface to UP
 */
int tunnel_up(const char *dev)
{
	struct ifreq ifr;
	int fd;

	strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;

	if (ioctl(fd, SIOCGIFFLAGS, &ifr)) {
		close(fd);
		return -1;
	}
	ifr.ifr_flags |= IFF_UP;

	if (ioctl(fd, SIOCSIFFLAGS, &ifr)) {
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

/**
 * Sets tunnel interface to DOWN
 **/
int tunnel_down(const char *dev)
{
	struct ifreq ifr;
	int fd;

	strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;

	if (ioctl(fd, SIOCGIFFLAGS, &ifr)) {
		close(fd);
		return -1;
	}
	ifr.ifr_flags &= ~IFF_UP;

	if (ioctl(fd, SIOCSIFFLAGS, &ifr)) {
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

/**
 * Delete tunnel interface
 **/
int tunnel_del(const char *dev)
{
	struct ip_tunnel_parm p;
	struct ifreq ifr;
	int fd;

	memset(&p, 0, sizeof(p));

	p.iph.version = 4;
	p.iph.ihl = 5;
	p.iph.protocol = IPPROTO_IPV6;
	p.i_flags |= SIT_ISATAP;
	strncpy(p.name, dev, IFNAMSIZ);

	strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	ifr.ifr_ifru.ifru_data = (void*)&p;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		return -1;
	}
	
	if (ioctl(fd, SIOCDELTUNNEL, &ifr)) {
		close(fd);
		return -1;
	}
	close(fd);

	return 0;
}

/**
 * Sets interface MTU
 **/
int tunnel_set_mtu(const char *dev, int mtu)
{
	struct ifreq ifr;
	int fd;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	ifr.ifr_mtu = mtu;
	if (ioctl(fd, SIOCSIFMTU, &ifr) < 0) {
		close(fd);
		return -1;
	}
	close(fd);

	return 0;
}



/**
 * Adds IPv4 address to tunnel PRL
 **/
int tunnel_add_prl(const char *dev, uint32_t addr, int default_rtr)
{
	struct ip_tunnel_prl p;
	struct ifreq ifr;
	int fd;

	memset(&p, 0, sizeof(p));
	p.addr = addr;
	if (default_rtr)
		p.flags |= PRL_DEFAULT;

	strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	ifr.ifr_ifru.ifru_data = (void*)&p;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;
	
	if (ioctl(fd, SIOCADDPRL, &ifr)) {
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

/**
 * Removes IPv4 address from tunnel PRL
 **/
int tunnel_del_prl(const char *dev, uint32_t addr)
{
	struct ip_tunnel_prl p;
	struct ifreq ifr;
	int fd;

	memset(&p, 0, sizeof(p));
	p.addr = addr;

	strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	ifr.ifr_ifru.ifru_data = (void*)&p;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;
	
	if (ioctl(fd, SIOCDELPRL, &ifr)) {
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}



