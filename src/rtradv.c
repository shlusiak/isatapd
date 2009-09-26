#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <signal.h>
#include <fcntl.h>
#include <syslog.h>
#include <errno.h>
#include <sys/time.h>
#include <time.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/icmp6.h>

#ifdef HAVE_CONFIG_H
	#include "config.h"
#endif

#include "prl.h"
#include "isatap.h"

#include "rtradv.h"




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
				/* pretend to be a spurious wake-up */
				errno = EAGAIN;
				return -1;
			}
		}
	}

	return val;
}




static int
parseadv (const uint8_t *buf, size_t len,
          struct PRLENTRY *pr){

	const struct nd_router_advert *ra =
		(const struct nd_router_advert *)buf;
	const uint8_t *ptr;

	/* checks if the packet is a Router Advertisement */
	if ((len < sizeof (struct nd_router_advert)) ||
	    (ra->nd_ra_type != ND_ROUTER_ADVERT) ||
	    (ra->nd_ra_code != 0))
		return -1;

#if 0 /* VERBOSE */
		unsigned v;

		/* Hop limit */
		puts ("");
		fputs (_("Hop limit                 :    "), stdout);
		v = ra->nd_ra_curhoplimit;
		if (v != 0)
			printf (_("      %3u"), v);
		else
			fputs (_("undefined"), stdout);
		printf (_(" (      0x%02x)\n"), v);

		v = ra->nd_ra_flags_reserved;
		printf (_("Stateful address conf.    :          %3s\n"),
		        gettext((v & ND_RA_FLAG_MANAGED) ? N_ ("Yes") : N_("No")));
		printf (_("Stateful other conf.      :          %3s\n"),
		        gettext((v & ND_RA_FLAG_OTHER) ? N_ ("Yes") : N_("No")));
		printf (_("Router preference         :       %6s\n"),
				pref_i2n (v));

		/* Router lifetime */
		fputs (_("Router lifetime           : "), stdout);
		v = ntohs (ra->nd_ra_router_lifetime);
		printf (_("%12u (0x%08x) %s\n"), v, v,
		        ngettext ("second", "seconds", v));

		/* ND Reachable time */
		fputs (_("Reachable time            : "), stdout);
		v = ntohl (ra->nd_ra_reachable);
		if (v != 0)
			printf (_("%12u (0x%08x) %s\n"), v, v,
			        ngettext ("millisecond", "milliseconds", v));
		else
			fputs (" unspecified (0x00000000)\n", stdout);

		/* ND Retransmit time */
		fputs ("Retransmit time           : ", stdout);
		v = ntohl (ra->nd_ra_retransmit);
		if (v != 0)
			printf ("%12u (0x%08x) %s\n", v, v,
			        ngettext ("millisecond", "milliseconds", v));
		else
			fputs (" unspecified (0x00000000)\n", stdout);
#endif 

	/* RFC 5214 8.3.4, extract the router lifetime from RA and
	 * set timer for the next RS
	 */

	/**TODO:Include Prefix/Route Information Option lifetimes **/
	double router_lifetime; /* in secs */
	unsigned v;

	router_lifetime =
		(double) pr->interval;

	v = ntohs (ra->nd_ra_router_lifetime);
	if (v > 5 && (double)v*0.8 < router_lifetime)
	{
		router_lifetime = (double)v * 0.8; /* 80% of lifetime */
	}

	len -= sizeof (struct nd_router_advert);

	/* parses options */
	ptr = buf + sizeof (struct nd_router_advert);

#if 0
	while (len >= 8)
	{
		uint16_t optlen;

		optlen = ((uint16_t)(ptr[1])) << 3;
		if ((optlen == 0) || /* invalid length */
		    (len < optlen)   /* length > remaining bytes */)
			break;

		len -= optlen;

		/* only prefix are shown if not verbose */
		switch (ptr[0])
		{
			case ND_OPT_SOURCE_LINKADDR:
// 				printf (" Source link-layer address: ",
// 					stdout);
// 				printmacaddress (ptr + 2, optlen - 2);
				break;

			case ND_OPT_TARGET_LINKADDR:
				break; /* ignore */

			case ND_OPT_PREFIX_INFORMATION:
// 				if (parseprefix ((const struct nd_opt_prefix_info *)ptr,
// 				                 optlen, verbose))
// 					return -1;
				break;

			case ND_OPT_REDIRECTED_HEADER:
				break; /* ignore */

			case ND_OPT_MTU:
// 				parsemtu ((const struct nd_opt_mtu *)ptr);
				break;

			case 24: /* RFC4191 */
// 				parseroute (ptr);
				break;

			case 25: /* RFC Ed queued draft-jeong-dnsop-ipv6-dns-discovery-12 */
// 				parserdnss (ptr);
				break;
		}
		/* skips unrecognized option */

		ptr += optlen;
	}
#endif

	pr->next_timeout = (int)(router_lifetime * 1000.0);
	pr->rs_sent = 0;

	return 0;
}




ssize_t recvadv(int fd, int ifindex)
{
	ssize_t val = 0;
	char str[INET6_ADDRSTRLEN];
 
	/* receives an ICMPv6 packet */
	/**TODO: use interface MTU as buffer size **/

	uint8_t buf[1460];
	struct sockaddr_in6 addr;
	struct PRLENTRY *pr;

        val = recvfromLL (fd, buf, sizeof (buf),
                                MSG_WAITALL, &addr);
	if (val == -1)
	{
                if (errno == EINTR)
                {
                        perror("Receive interrupted by signal");
                }
                else if (errno != EAGAIN)
			perror ("Receiving ICMPv6 packet");
		return val;
	}

	
	if (ifindex != addr.sin6_scope_id) {
		if (inet_ntop (AF_INET6, &addr.sin6_addr,
			str, sizeof (str)) != NULL)
			syslog(LOG_INFO, "Ignoring Advertisement from %s (scope mismatch)", str);
		return val;
	}
	pr = findPR_by_addr6(&addr.sin6_addr);
	if (pr) {
		if (parseadv(buf, val, pr) < 0)
			return 0;
		if (inet_ntop (AF_INET6, &addr.sin6_addr,
			str, sizeof (str)) != NULL)
			syslog(LOG_INFO, "Advertisement from %s, next interval %d sec.\n", str, pr->next_timeout / 1000);
	} else {
		if (inet_ntop (AF_INET6, &addr.sin6_addr,
			str, sizeof (str)) != NULL)
			syslog(LOG_WARNING, "Ignoring Advertisement from %s (unsolicited)\n", str);
	}
 
        return val;

}