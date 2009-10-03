/*
 * rdisc.c      send router solicitations, receive router advertisements
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Authors:     Sascha Hlusiak, <mail@saschahlusiak.de>
 *              Kwong-Sang Yin, <kwong-sang.yin@boeing.com> 
 *              Fred Templin,   <fred.l.templin@boeing.com> 
 *
 */


#include <stdio.h>
#include <unistd.h>
#include <errno.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <syslog.h>


#ifdef HAVE_CONFIG_H
	#include <config.h>
#endif

#include "main.h"
#include "rdisc.h"
#include "isatap.h"


int create_rs_socket()
{
	int fd = socket (PF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
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
	return fd;
}

int send_rdisc(int fd, int ifindex, struct in6_addr *addr)
{
	struct sockaddr_in6 target;
	struct nd_router_solicit rs;

	if (ifindex == 0)
		return -1;

	memset(&target, 0, sizeof(target));
	memset(&rs, 0, sizeof(rs));
	target.sin6_addr = *addr;
	target.sin6_family = AF_INET6;
	target.sin6_scope_id = ifindex;

	rs.nd_rs_type = ND_ROUTER_SOLICIT;
	rs.nd_rs_code = 0;
	rs.nd_rs_cksum = 0;
	rs.nd_rs_reserved = 0;

	if (sendto(fd, &rs, sizeof(rs), 0,
			(const struct sockaddr *)&target,
			sizeof (target)) != sizeof(rs))
	{
		return -1;
	}
	return 0;
}



static ssize_t
recvfromLL (int fd, void *buf, size_t len, int flags,
            struct sockaddr_in6 *addr) 
{
	char cbuf[CMSG_SPACE (sizeof (int))];
	struct iovec iov =
	{
		.iov_base = buf,
		.iov_len = len
	};
	struct msghdr hdr =
	{
		.msg_name = addr,
		.msg_namelen = sizeof (*addr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = cbuf,
		.msg_controllen = sizeof (cbuf)
	};
	struct cmsghdr *cmsg;

        ssize_t val = recvmsg (fd, &hdr, flags);
        if (val == -1)
		return val;

	/* ensures the hop limit is 255 */
	for (cmsg = CMSG_FIRSTHDR (&hdr);
	     cmsg != NULL;
	     cmsg = CMSG_NXTHDR (&hdr, cmsg))
	{
		if ((cmsg->cmsg_level == IPPROTO_IPV6)
		 && (cmsg->cmsg_type == IPV6_HOPLIMIT))
		{
			if (255 != *(int *)CMSG_DATA (cmsg))
			{
				/* ignore */
				return 0;
			}
		}
	}

	return val;
}




static int
parseadv (const struct nd_router_advert *ra, int len, struct PRLENTRY *pr)
{
	/* RFC 5214 8.3.4, extract the router lifetime from RA and
	 * set timer for the next RS
	 */

	/**TODO:Include Prefix/Route Information Option lifetimes **/
	double router_lifetime; /* in secs */
	unsigned v;

	router_lifetime =
		(double) pr->default_timeout;

	v = ntohs (ra->nd_ra_router_lifetime);
	if (v > 5 && (double)v*0.8 < router_lifetime)
	{
		router_lifetime = (double)v * 0.8; /* 80% of lifetime */
	}

	pr->next_timeout = (int)(router_lifetime * 1000.0);
	if (pr->next_timeout < DEFAULT_MINROUTERSOLICITINTERVAL)
		pr->next_timeout = DEFAULT_MINROUTERSOLICITINTERVAL;
	pr->rs_sent = 0;

	return 0;
}




ssize_t recvadv(int fd, int ifindex)
{
	ssize_t val = 0;
	char str[INET6_ADDRSTRLEN];
	struct nd_router_advert *ra;
 
	/* receives an ICMPv6 packet */
	/**TODO: use interface MTU as buffer size **/

	uint8_t buf[1460];
	struct sockaddr_in6 addr;
	struct PRLENTRY *pr;

        val = recvfromLL (fd, buf, sizeof (buf),
                                MSG_WAITALL, &addr);
	if (val == -1)
	{
		perror ("Receiving ICMPv6 packet");
		return val;
	}

	/* ignore data */
        if (val == 0)
    		return 0;

	/* checks if the packet is a Router Advertisement and ignore, if not */
	ra =  (struct nd_router_advert *)buf;
	if ((val < sizeof (struct nd_router_advert)) ||
	    (ra->nd_ra_type != ND_ROUTER_ADVERT) ||
	    (ra->nd_ra_code != 0))
		return 0;
	
	/* Check matching  scope */
	if (ifindex != addr.sin6_scope_id) {
		if (verbose >= 1 && inet_ntop (AF_INET6, &addr.sin6_addr,
			str, sizeof (str)) != NULL)
			syslog(LOG_INFO, "Ignoring Advertisement from %s (scope mismatch)", str);
		return val;
	}

	/* Find internal PRL entry */
	pr = find_internal_pdr_by_addr6(&addr.sin6_addr);
	if (pr) {
		if (parseadv(ra, val, pr) < 0)
			return 0;
		if (verbose >= 0 && inet_ntop (AF_INET6, &addr.sin6_addr,
			str, sizeof (str)) != NULL)
			syslog(LOG_INFO, "Advertisement from %s, next interval %d sec.\n", str, pr->next_timeout / 1000);
	} else {
		if (verbose >= 1 && inet_ntop (AF_INET6, &addr.sin6_addr,
			str, sizeof (str)) != NULL)
			syslog(LOG_WARNING, "Ignoring Advertisement from %s (unsolicited)\n", str);
	}
 
        return val;

}


