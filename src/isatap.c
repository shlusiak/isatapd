#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <signal.h>
#include <fcntl.h>
#include <syslog.h>
#include <errno.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/utsname.h>

#define _GNU_SOURCE
#include <getopt.h>

#ifdef HAVE_CONFIG_H
	#include "config.h"
#endif

#include "main.h"
#include "tunnel.h"
#include "rdisc.h"
#include "prl.h"


/**
 * Sends out one ISATAP-RS to a specified IPv4 address
 **/
static int solicitate_router(int fd, char* tunnel_name, uint32_t router) {
	struct in6_addr addr6;
	static char addrstr[INET6_ADDRSTRLEN];

	addr6.s6_addr32[0] = htonl(0xfe800000);
	addr6.s6_addr32[1] = htonl(0x00000000);
	addr6.s6_addr32[2] = htonl(0x00005efe);
	addr6.s6_addr32[3] = router;

	if (verbose >= 2) {
		syslog(LOG_INFO, "Soliciting %s\n", inet_ntop(AF_INET6, &addr6, addrstr, sizeof(addrstr)));
	}
	if (send_rdisc(fd, tunnel_name, &addr6) < 0) {
		if (verbose >= -1) {
			syslog(LOG_ERR, "send_rdisc: %s\n", strerror(errno));
		}
		return -1;
	}
	return 0;
}

/**
 * Resolves one router name and appends found IPv4 Addresses
 * to internal PRL
 **/
int add_router_name_to_prl(const char* host, int interval)
{
	struct addrinfo *addr_info, *p, hints;
	int err;

	if (host == NULL)
		return 0;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_protocol=IPPROTO_IPV6;
	err = getaddrinfo(host, NULL, &hints, &addr_info);

	if (err) {
		if (verbose >= 0)
			syslog(LOG_WARNING, "add_prl_entry: %s: %s\n", host, gai_strerror(err));
		/* host not found is not fatal */
		return 0;
	}

	p=addr_info;
	while (p)
	{
		struct in_addr addr;
		struct PRLENTRY* pr;

		addr = ((struct sockaddr_in*)(p->ai_addr))->sin_addr;
		if (!findPR(addr.s_addr)) {
			if (verbose >= 1)
				syslog(LOG_INFO, "Adding PDR %s\n", inet_ntoa(addr));
			pr=newPR();
			pr->ip = addr.s_addr;
			pr->interval = interval;
			addPR(pr);
		} else {
			if (verbose >=1)
				syslog(LOG_INFO, "Ignoring duplicate PDR %s\n", inet_ntoa(addr));
		}

		p=p->ai_next;
	}
	freeaddrinfo(addr_info);

	return 0;
}

/**
 * Drops privileges
 * Add PRL to kernel
 * Loop and send RS
 */
int run_solicitation_loop(char* tunnel_name) {
	struct PRLENTRY* pr;
	int fd;

	fd = create_rs_socket();

	pr = getFirstPR();
	while (pr) {
		if (tunnel_add_prl(tunnel_name, pr->ip, 1) < 0) {
			/* hopefully not fatal. could be EEXIST */
			if (verbose >= 2)
				syslog(LOG_ERR, "tunnel_add_prl: %s\n", strerror(errno));
		}
		pr = pr->next;
	}

	/* Drop privileges */
	setgid(65534);
	setuid(65534);

	pr = getFirstPR();
	while (1) {
		while (pr) {
			if (solicitate_router(fd, tunnel_name, pr->ip) < 0)
				return -1;
			pr = pr->next;
		}
		pr = getFirstPR();

		printf("Sleeping %d sec\n", pr->interval);
		sleep(pr->interval);
	}
	close(fd);
	return 0;
}


