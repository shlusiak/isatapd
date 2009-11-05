/*
 * isatap.c     Loop over router solicitations, handle PRL
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

#include <net/if.h>
#include <netdb.h>
#include <arpa/inet.h>


#ifdef HAVE_CONFIG_H
	#include "config.h"
#endif

#include "main.h"
#include "tunnel.h"
#include "rdisc.h"
#include "isatap.h"


static struct PRLENTRY* prl_head = NULL;


static void sighup_handler_child() {
	exit(EXIT_CHECK_PRL);
}


void flush_internal_prl() {
	while (prl_head)
		del_internal_pdr(prl_head);
}

void add_internal_pdr(struct PRLENTRY* pr) {
	pr->next = prl_head;
	prl_head = pr;
}

struct PRLENTRY* new_internal_pdr() {
	struct PRLENTRY* n;
	n = (struct PRLENTRY*)malloc(sizeof(struct PRLENTRY));

	n->ip = 0;
	n->next = NULL;
	n->sibling = NULL;
	n->default_timeout = 0;
	n->next_timeout = 0;
	n->rs_sent = 0;
	n->stale = 0;
	memset(&n->addr6, 0, sizeof(n->addr6));

	return n;
}

struct PRLENTRY* del_internal_pdr(struct PRLENTRY* pr) {
	struct PRLENTRY* prev = prl_head;
	if (pr == prl_head) {
		prl_head = pr->next;
		free(pr);
		return prl_head;
	}
	while (prev) {
		if (prev->next == pr) {
			prev->next = pr->next;
			free(pr);
			return prev->next;
		}
		prev = prev->next;
	}
	return NULL;
}

struct PRLENTRY* find_internal_pdr_by_addr(uint32_t ip) {
	struct PRLENTRY* cur = prl_head;
	while (cur) {
		if (cur->ip == ip)
			return cur;
		cur = cur->next;
	}
	return NULL;
}

struct PRLENTRY* find_internal_pdr_by_addr6(struct in6_addr *addr) {
	struct PRLENTRY* cur = prl_head;
	while (cur) {
		if (bcmp(&cur->addr6.sin6_addr, addr, sizeof(struct in6_addr)) == 0) 
			return cur;
		cur = cur->next;
	}
	return NULL;
}

struct PRLENTRY* get_first_internal_pdr() {
	return prl_head;
}




/**
 * Return 0 if IPv4 address is global
 * Return 1 if IPv4 Address is private
 **/
static int ipv4_is_private(uint32_t addr) {
	uint8_t *b8 = (uint8_t*)&addr;
	switch (b8[0]) {
	case 0:
	case 10:
	case 14:
	case 24:
	case 39:
	case 127:
		return 1;
		break;
	case 128:
		if (b8[1] == 0)
			return 1;
		break;
	case 169:
		if (b8[1] == 254)
			return 1;
		break;
	case 172:
		if ((b8[1] >= 16) && (b8[1] <= 31))
			return 1;
		break;
	case 191:
		if (b8[1] == 255)
			return 1;
		break;
	case 192:
		switch (b8[1]) {
		case 0:
			if ((b8[2] == 0) || (b8[2] == 2))
				return 1;
			break;
		case 88:
			if (b8[2] == 99)
				return 1;
			break;
		case 168:
			return 1;
		default:
			break;
		}
		break;
	case 198:
		if ((b8[1] == 18) || (b8[1] == 19))
			return 1;
		break;
	case 223:
		if ((b8[1] == 255) && (b8[2] == 255))
			return 1;
	default:
		break;
	}
	return 0;
}




/**
 * Sends out one ISATAP-RS to a specified IPv6 address
 **/
static int solicitate_router(int fd, int ifindex, struct sockaddr_in6 *addr6) {
	if (verbose >= 1) {
		static char addrstr[INET6_ADDRSTRLEN];
		syslog(LOG_INFO, "Soliciting %s\n", inet_ntop(AF_INET6, &addr6->sin6_addr, addrstr, sizeof(addrstr)));
	}
	if (send_rdisc(fd, ifindex, &addr6->sin6_addr) < 0) {
		if (verbose >= -1) {
			syslog(LOG_ERR, "send_rdisc: %s\n", strerror(errno));
		}
		return -1;
	}
	return 0;
}

/**
 * Resolves one router name and appends the found IPv4 Addresses
 * to internal PRL
 **/
int add_router_name_to_internal_prl(const char* host, int interval)
{
	struct addrinfo *addr_info, *p, hints;
	int err;

	if (host == NULL)
		return -1;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_protocol=IPPROTO_IPV6;
	err = getaddrinfo(host, NULL, &hints, &addr_info);

	if (err) {
		if (verbose >= 0)
			syslog(LOG_WARNING, "add_router_name_to_internal_prl: %s: %s\n", host, gai_strerror(err));
		/* host not found is less fatal */
		return 0;
	}

	p=addr_info;
	while (p)
	{
		struct in_addr addr;
		struct PRLENTRY* pr;
		
		addr = ((struct sockaddr_in*)(p->ai_addr))->sin_addr;
		pr = find_internal_pdr_by_addr(addr.s_addr);
		if (!pr) {
			if (verbose >= 1)
				syslog(LOG_INFO, "Adding internal PDR %s\n", inet_ntoa(addr));
			/* Add local address (not always RFC conform) */
			pr=new_internal_pdr();
			pr->ip = addr.s_addr;
			pr->default_timeout = interval;
			pr->addr6.sin6_addr.s6_addr32[0] = htonl(0xfe800000);
			pr->addr6.sin6_addr.s6_addr32[1] = htonl(0x00000000);
			pr->addr6.sin6_addr.s6_addr32[2] = htonl(0x00005efe);
			pr->addr6.sin6_addr.s6_addr32[3] = addr.s_addr;
			
			add_internal_pdr(pr);
			
			/* Add RFC conform global address as well, if saddr is public */
			if (!ipv4_is_private(addr.s_addr)) {
				pr->sibling = new_internal_pdr();
				pr->sibling->sibling = pr;
				pr=pr->sibling;
				
				pr->ip = addr.s_addr;
				pr->default_timeout = interval;
				pr->addr6.sin6_addr.s6_addr32[0] = htonl(0xfe800000);
				pr->addr6.sin6_addr.s6_addr32[1] = htonl(0x00000000);
				pr->addr6.sin6_addr.s6_addr32[2] = htonl(0x02005efe);
				pr->addr6.sin6_addr.s6_addr32[3] = addr.s_addr;

				add_internal_pdr(pr);
			}
		} else {
			if (verbose >=2)
				syslog(LOG_INFO, "%s duplicate internal PDR %s\n",
					pr->stale?"Refreshing":"Ignoring",
					inet_ntoa(addr));
			pr->stale = 0; /* Refresh PRL entry */
			if (pr->sibling)
				pr->sibling->stale = 0;
			
		}

		p=p->ai_next;
	}
	freeaddrinfo(addr_info);

	return 0;
}

int prune_kernel_prl(const char *dev) {
	struct PRLENTRY* pr;
	
	pr=get_first_internal_pdr();
	while (pr) {
		if (pr->stale) {
			struct in_addr ia;
			ia.s_addr = pr->ip;
			if (verbose >= 1)
				syslog(LOG_INFO, "Removing old PDR %s from kernel\n", inet_ntoa(ia));
			tunnel_del_prl(dev, pr->ip);
			pr = del_internal_pdr(pr);
		} else 
			pr = pr->next;
	}
  
	return 0;
}

/**
 * Drops privileges
 * Add PRL to kernel
 * Loop and send RS
 * 
 * Returns:
 *   EXIT_ERROR_FATAL
 *   EXIT_ERROR_LAYER2
 *   EXIT_CHECK_PRL
 */
int run_solicitation_loop(char* tunnel_name, int check_dns_timeout) {
	struct PRLENTRY* pr;
	int fd;
	int ifindex;
	int check_dns;

	srand((unsigned int)time(NULL));
	
	pr = get_first_internal_pdr();
	if (pr == NULL) {
		if (verbose >= -2)
			syslog(LOG_ERR, "PRL empty!\n");
		return EXIT_ERROR_FATAL;
	}

	ifindex = if_nametoindex(tunnel_name);
	if (ifindex < 0) {
		perror("if_nametoindex");
		return EXIT_ERROR_FATAL;
	}

	fd = create_rs_socket();
	if (fd < 0) {
		if (verbose >= -2)
			syslog(LOG_ERR, "create_rs_socket: invalid fd\n");
		return EXIT_ERROR_FATAL;
	}

	/* Add internal PRL to kernel PRL */
	while (pr) {
		if (tunnel_add_prl(tunnel_name, pr->ip, 1) < 0) {
			/* hopefully not fatal. could be EEXIST */
			if (verbose >= 2 && errno != EEXIST)
				syslog(LOG_ERR, "tunnel_add_prl: %s\n", strerror(errno));
		} else if (verbose >= 2) {
			struct in_addr ia;
			ia.s_addr = pr->ip;
			syslog(LOG_INFO, "Adding PDR %s to kernel\n", inet_ntoa(ia));
		}
		/* Calculate random delay in ms */
		pr->next_timeout = (int)(1000.0 *
		    (double)rand() *
		    (double)MAX_RTR_SOLICITATION_DELAY /
		    (double)RAND_MAX);
		pr = pr->next;
	}

	/* Drop privileges */
	/* TODO: Make this configurable */
	setgid(65534);
	setuid(65534);
	
	signal(SIGTERM, SIG_IGN);
	signal(SIGINT, SIG_IGN);
	signal(SIGHUP, sighup_handler_child);

	check_dns = (check_dns_timeout > 0);

	while (!check_dns || check_dns_timeout > 0) {
		fd_set fds;
		struct timeval timeout;
		int ret;
		int next_timeout;
		
		pr = get_first_internal_pdr();
		
		if (check_dns)
			next_timeout = check_dns_timeout;
		else
			next_timeout = pr->next_timeout;
		
		while (pr) {
			if (pr->next_timeout < next_timeout)
				next_timeout = pr->next_timeout;
			pr = pr->next;
		}

		FD_ZERO(&fds);
		FD_SET(fd, &fds);
		timeout.tv_sec = next_timeout / 1000;
		timeout.tv_usec = (next_timeout % 1000) * 1000;

		ret = select(fd+1, &fds, NULL, NULL, &timeout);
		if (ret < 0) {
			close(fd);
			perror("select");
			return EXIT_ERROR_FATAL;
		}
		
		if ((ret != 0) && (FD_ISSET(fd, &fds))) {
			/* Data available from socket */
			next_timeout = next_timeout - timeout.tv_sec * 1000 - timeout.tv_usec / 1000;
			if (recvadv(fd, ifindex) < 0) {
				perror("recvadv");
				return EXIT_ERROR_LAYER2;
			}
		}
		if (check_dns)
			check_dns_timeout -= next_timeout;

		/* Decrease timeout of all PRL entries and fire solicitation if necessary */
		pr = get_first_internal_pdr();
		while (pr) {
			pr->next_timeout -= next_timeout;
			if (pr->next_timeout <= 0) {
				if (solicitate_router(fd, ifindex, &pr->addr6) < 0) {
					return EXIT_ERROR_LAYER2;
				}
				pr->rs_sent++;
				if (pr->rs_sent >= MAX_RTR_SOLICITATIONS) {
					pr->rs_sent = 0;
					pr->next_timeout += DEFAULT_MINROUTERSOLICITINTERVAL * 1000;
				} else pr->next_timeout += RTR_SOLICITATION_INTERVAL * 1000;
			}
			pr = pr->next;
		}
	}
	close(fd);
	return EXIT_CHECK_PRL;
}

