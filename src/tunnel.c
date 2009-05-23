#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <linux/if_tunnel.h>
#include <sys/ioctl.h>
#include <net/if.h>

#ifdef HAVE_CONFIG_H
	#include <config.h>
#endif


#include "tunnel.h"


uint32_t get_if_addr(const char *dev)
{
	struct ifreq ifr;
	int fd;
	int err;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	err = ioctl(fd, SIOCGIFADDR, &ifr);
	if (err) {
		perror("ioctl");
		close(fd);
		return 0;
	}
	close(fd);
	return ((struct sockaddr_in *) (&ifr.ifr_addr))->sin_addr.s_addr;
}

int tunnel_add(const char *dev,
		const char *link,
		uint32_t saddr)
{
	struct ip_tunnel_parm p;
	struct ifreq ifr;
	int fd;
	int err;

	memset(&p, 0, sizeof(p));

	p.iph.version = 4;
	p.iph.ihl = 5;
	p.iph.protocol = IPPROTO_IPV6;
	p.iph.saddr = saddr;
	p.iph.frag_off = htons(IP_DF);
	p.i_flags |= SIT_ISATAP;
	strncpy(p.name, dev, IFNAMSIZ);
	p.link = if_nametoindex(link);
	if (p.link <= 0) {
		perror("get_ifindex");
		return -1;
	}

	strncpy(ifr.ifr_name, "sit0", IFNAMSIZ);
	ifr.ifr_ifru.ifru_data = (void*)&p;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("socket");
		return -1;
	}
	err = ioctl(fd, SIOCADDTUNNEL, &ifr);
	if (err)
		perror("ioctl");
	close(fd);

	return err;
}

int tunnel_up(const char *dev)
{
	struct ifreq ifr;
	int fd;
	int err;

	strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;
	err = ioctl(fd, SIOCGIFFLAGS, &ifr);
	if (err) {
		perror("SIOCGIFFLAGS");
		close(fd);
		return -1;
	}
	ifr.ifr_flags |= IFF_UP;

	err = ioctl(fd, SIOCSIFFLAGS, &ifr);
	if (err)
		perror("SIOCSIFFLAGS");
	close(fd);
	return err;
}

int tunnel_down(const char *dev)
{
	struct ifreq ifr;
	int fd;
	int err;

	strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;
	err = ioctl(fd, SIOCGIFFLAGS, &ifr);
	if (err) {
		perror("SIOCGIFFLAGS");
		close(fd);
		return -1;
	}
	ifr.ifr_flags &= ~IFF_UP;

	err = ioctl(fd, SIOCSIFFLAGS, &ifr);
	if (err)
		perror("SIOCSIFFLAGS");
	close(fd);
	return err;
}

int tunnel_del(const char *dev)
{
	struct ip_tunnel_parm p;
	struct ifreq ifr;
	int fd;
	int err;

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
		perror("socket");
		return -1;
	}
	err = ioctl(fd, SIOCDELTUNNEL, &ifr);
	if (err)
		perror("ioctl");
	close(fd);

	return err;
}

int tunnel_add_prl(const char *dev, uint32_t addr, int default_rtr)
{
	struct ip_tunnel_prl p;
	struct ifreq ifr;
	int err;
	int fd;

	memset(&p, 0, sizeof(p));
	p.addr = addr;
	if (default_rtr)
		p.flags |= PRL_DEFAULT;

	strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	ifr.ifr_ifru.ifru_data = (void*)&p;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	err = ioctl(fd, SIOCADDPRL, &ifr);
	if (err)
		perror("ioctl");
	close(fd);
	return err;
}


















