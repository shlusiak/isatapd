/*
 * rdisc.c         send router solicitation message
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
#include <unistd.h> 

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>


#ifdef HAVE_CONFIG_H
	#include <config.h>
#endif

#include "rdisc.h"


int send_rdisc(const char *dev, struct in6_addr *addr)
{
	int fd = socket (PF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	struct sockaddr_in6 target;
	struct nd_router_solicit rs;
	int i;

	if (fd < 0)
		return -1;

	i = 1;
	if (setsockopt (fd, SOL_SOCKET, SO_DONTROUTE, 
			&i, sizeof(int)) < 0) {
		close(fd);
		return -1;
	}

	i = 255;
	if (setsockopt (fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS,
	                &i, sizeof (i)) < 0) {
		close(fd);
		return -1;
	}

	i = 255;
	if (setsockopt (fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
	                &i, sizeof (i)) < 0) {
		close(fd);
		return -1;
	}
	
	i = 1;
	if (setsockopt (fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT,
	                &i, sizeof (int)) < 0) {
		close(fd);
		return -1;
	}

	memset(&target, 0, sizeof(target));
	memset(&rs, 0, sizeof(rs));
	target.sin6_addr = *addr;
	target.sin6_family = AF_INET6;
	target.sin6_scope_id = if_nametoindex(dev);
	if (target.sin6_scope_id == 0) {
		close(fd);
		return -1;
	}

	rs.nd_rs_type = ND_ROUTER_SOLICIT;
	rs.nd_rs_code = 0;
	rs.nd_rs_cksum = 0;
	rs.nd_rs_reserved = 0;

	if (sendto(fd, &rs, sizeof(rs), 0,
			(const struct sockaddr *)&target,
			sizeof (target)) != sizeof(rs))
	{
		close(fd);
		return -1;
	}

	close(fd);
	return 0;
}
