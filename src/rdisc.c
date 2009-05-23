#include <stdio.h>
#include <unistd.h> 

#include <net/if.h> /* if_nametoindex() */

#include <netinet/in.h>
#include <netinet/icmp6.h>


#ifdef HAVE_CONFIG_H
	#include <config.h>
#endif


int send_rdisc(const char *dev, struct in6_addr *addr)
{
	int fd = socket (PF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	struct sockaddr_in6 target;
	struct nd_router_solicit rs;
	int i;

	if (fd < 0) {
		perror("socket");
		return -1;
	}
	i = 1;
	setsockopt (fd, SOL_SOCKET, SO_DONTROUTE, &i, sizeof(int));

	i = 255;
	setsockopt (fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS,
	            &i, sizeof (i));

	i = 255;
	setsockopt (fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
	            &i, sizeof (i));
	
	i = 1;
	setsockopt (fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT,
	            &i, sizeof (int));

	memset(&target, 0, sizeof(target));
	memset(&rs, 0, sizeof(rs));
	target.sin6_addr = *addr;
	target.sin6_family = AF_INET6;
	target.sin6_scope_id = if_nametoindex(dev);
	if (target.sin6_scope_id == 0)
		perror("if_nametoindex");

	rs.nd_rs_type = ND_ROUTER_SOLICIT;
	rs.nd_rs_code = 0;
	rs.nd_rs_cksum = 0;
	rs.nd_rs_reserved = 0;

	if (sendto(fd, &rs, sizeof(rs), 0,
			(const struct sockaddr *)&target,
			sizeof (target)) != sizeof(rs))
	{
		perror ("Sending ICMPv6 packet");
	}

	close(fd);
	return 0;
}


