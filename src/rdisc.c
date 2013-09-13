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
#include <sys/socket.h>


#ifdef HAVE_CONFIG_H
	#include <config.h>
#endif

#include "main.h"
#include "rdisc.h"
#include "isatap.h"


/**
 * Creates a IPv6, ICMPv6 RAW-Socket
 * return: fd or -1
 **/
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

/**
 * Sends a RS to addr, from ifindex
 **/
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


/**
 * Receive a LL packet from socket
 * return 0: ignore package
 *       -1: error
 *       >0: success
 **/
static ssize_t recvfromLL (int fd, void *buf, size_t len, int flags,
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

        ssize_t val = recvmsg(fd, &hdr, flags);
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
			int* data = (int *)CMSG_DATA (cmsg);
			if (255 != *data)
			{
				/* ignore */
				return 0;
			}
		}
	}

	return val;
}


/**
 * Parse received RA and set new time out for RS
 **/
static int parseadv (const struct nd_router_advert *ra, int len, struct PRLENTRY *pr)
{
	/* RFC 5214 8.3.4, extract the router lifetime from RA and
	 * set timer for the next RS
	 */

	double router_lifetime; /* in secs */
	double v;
	const uint8_t *ptr;
	
	router_lifetime = (double)pr->default_timeout;

	v = 0.8 * (double)ntohs(ra->nd_ra_router_lifetime);
	if (v > 0 && v < router_lifetime)
		router_lifetime = v; /* 80% of lifetime */

	if (verbose >= 2)
		syslog(LOG_INFO, "  Router lifetime %d sec\n", 
			ntohs(ra->nd_ra_router_lifetime));
	
	ptr = (uint8_t*)ra + sizeof(struct nd_router_advert);
	len -= sizeof (struct nd_router_advert);
	
	while (len >= 8)
	{
		uint16_t optlen;

		optlen = ((uint16_t)(ptr[1])) << 3;
		if ((optlen == 0) || /* invalid length */
		    (len < optlen) /* length > remaining bytes */)
			break;

		len -= optlen;

		switch (ptr[0])
		{
			case ND_OPT_SOURCE_LINKADDR:
			case ND_OPT_TARGET_LINKADDR:
			case ND_OPT_REDIRECTED_HEADER:
			case ND_OPT_MTU:
			case 25: /* RFC Ed queued draft-jeong-dnsop-ipv6-dns-discovery-12 */
				break;

			case ND_OPT_PREFIX_INFORMATION: {
			  	char str[INET6_ADDRSTRLEN];
				struct nd_opt_prefix_info *pi;
				pi = (struct nd_opt_prefix_info*)ptr;

				if (optlen < sizeof (struct nd_opt_prefix_info))
					return -1;

				if (verbose >= 1) {
	  				/* displays prefix informations */
					if (inet_ntop (AF_INET6, &pi->nd_opt_pi_prefix, str,
						sizeof (str)) == NULL)
						return -1;

					syslog(LOG_INFO, "  Prefix %s/%u, lifetime %d sec\n", 
					       str,
					       pi->nd_opt_pi_prefix_len,
					       ntohl(pi->nd_opt_pi_preferred_time));
				}

				v = 0.8 * (double)ntohl(pi->nd_opt_pi_preferred_time);
				if (v > 0 && v < router_lifetime)
					router_lifetime = v; /* 80% of preferred lifetime */

				v = 0.8 * (double)ntohl(pi->nd_opt_pi_valid_time);
				if (v > 0 && v < router_lifetime)
					router_lifetime = v; /* 80% of valid lifetime */

				break;
			}


			case 24: { /* RFC4191, specific route */
				uint8_t optlen = ptr[1], plen = ptr[2];
				char str[INET6_ADDRSTRLEN];
				uint32_t lifetime; 
				struct in6_addr dst = in6addr_any;
				
				if ((optlen > 3) || (plen > 128) || (optlen < ((plen + 127) >> 6)))
					return -1;

				memcpy (dst.s6_addr, ptr + 8, (optlen - 1) << 3);

				lifetime = ntohl(((const uint32_t *)ptr)[1]);
				
				if (verbose >= 2) {
					if (inet_ntop (AF_INET6, &dst, str, sizeof (str)) == NULL)
						return -1;
					syslog(LOG_INFO, "  Route %s/%u, lifetime %d sec\n", 
						str,
						plen,
						lifetime);
				}
				
				v = 0.8 * (double)lifetime;
				if (v > 0 && v < router_lifetime)
					router_lifetime = v; /* 80% of route lifetime */

				break;
			}
		}

		ptr += optlen;
	}

	pr->next_timeout = (int)(router_lifetime * 1000.0);
	if (pr->next_timeout < DEFAULT_MINROUTERSOLICITINTERVAL)
		pr->next_timeout = DEFAULT_MINROUTERSOLICITINTERVAL;
	pr->rs_sent = 0;

	if (verbose >= 2)
		syslog(LOG_INFO, " Setting next timeout to %d sec\n", 
			pr->next_timeout / 1000);

	return 0;
}



/**
 * Receive a RA from an interface and parse it
 * Returns:
 *  -1: error
 *   0: ignore/success
 *   1: success
 **/
int recvadv(int fd, int ifindex)
{
	/* receives an ICMPv6 packet */
	/* TODO: use interface MTU as buffer size */
	ssize_t val = 0;
	char str[INET6_ADDRSTRLEN];
	struct nd_router_advert *ra;
	uint8_t buf[1460];
	struct sockaddr_in6 addr;
	struct PRLENTRY *pr;

        val = recvfromLL (fd, buf, sizeof (buf),
                                MSG_WAITALL, &addr);
	if (val == -1)
	{
		syslog(LOG_ERR, "Receiving ICMPv6 packet: %s\n", strerror(errno));
		return -1;
	}

	/* ignore data */
        if (val == 0)
    		return 0;

	/* checks if the packet is a Router Advertisement and ignore otherwise */
	ra =  (struct nd_router_advert *)buf;
	if ((val < sizeof (struct nd_router_advert)) ||
	    (ra->nd_ra_type != ND_ROUTER_ADVERT) ||
	    (ra->nd_ra_code != 0))
		return 0;
	
	/* Check matching scope */
	if (ifindex != addr.sin6_scope_id) {
		if (verbose >= 2 && inet_ntop (AF_INET6, &addr.sin6_addr,
			str, sizeof (str)) != NULL)
			syslog(LOG_INFO, "Ignoring Advertisement from %s (scope mismatch)", str);
		return 0;
	}

	/* Find internal PRL entry */
	pr = find_internal_pdr_by_addr6(&addr.sin6_addr);
	if (pr) {
		if (verbose >= 1 && inet_ntop (AF_INET6, &addr.sin6_addr,
			str, sizeof (str)) != NULL)
			syslog(LOG_INFO, "Advertisement from %s\n", str);
		
		/* Ignore unparsable advertisements */
		if (parseadv(ra, val, pr) < 0) {
			if (verbose >= 1 && inet_ntop (AF_INET6, &addr.sin6_addr,
				str, sizeof (str)) != NULL)
				syslog(LOG_INFO, "Ignoring Advertisement from %s (parse error)\n", str);
			return 0;
		}
		
		if (pr->sibling) {
			/* We already succeeded with that IPv4 router, so deprecate the sibling */
			if (verbose >= 2 && inet_ntop (AF_INET6, &pr->sibling->addr6.sin6_addr,
				str, sizeof (str)) != NULL)
				syslog(LOG_INFO, " (Not soliciting %s anymore)\n", str);
			
			/* NOTE: This does not delete the sibling in the parent process! */
			/* It will come up again when refreshing DNS */
			del_internal_pdr(pr->sibling);
			pr->sibling = NULL;
		}
		return 1;
	}
	
	if (verbose >= 1 && inet_ntop (AF_INET6, &addr.sin6_addr,
		str, sizeof (str)) != NULL)
		syslog(LOG_WARNING, "Ignoring Advertisement from %s (unsolicited)\n", str);
	return 0;
}


