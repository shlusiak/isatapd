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
#include <pwd.h>
#include <grp.h>

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


void flush_internal_prl() {
	while (prl_head)
		del_internal_pdr(prl_head);
}


struct PRLENTRY* get_first_internal_pdr() {
	return prl_head;
}

/**
 * Add new PRL entry to head of list
 **/
void add_internal_pdr(struct PRLENTRY* pr) {
	pr->next = prl_head;
	prl_head = pr;
}

/**
 * Creates and zeros new internal PRL entry
 **/
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

/**
 * Delets a PRL entry from internal list
 * If NOT in list, returns NULL
 * If it was in list, return the following entry
 **/
struct PRLENTRY* del_internal_pdr(struct PRLENTRY* pr) {
	struct PRLENTRY* prev;
	if (pr == prl_head) {
		prl_head = pr->next;
		free(pr);
		return prl_head;
	}
	prev = prl_head;
	while (prev) {
		if (prev->next == pr) {
			prev->next = pr->next;
			free(pr);
			return prev->next;
		}
		prev = prev->next;
	}
	/* Not found in list */
	return NULL;
}

/**
 * Returns first PRL entry for given IPv4 address
 **/
struct PRLENTRY* find_internal_pdr_by_addr(uint32_t ip) {
	struct PRLENTRY* cur = prl_head;
	while (cur) {
		if (cur->ip == ip)
			return cur;
		cur = cur->next;
	}
	return NULL;
}

static int mycmp(void* a, void* b, int size) {
	while (size--)
		if (*((char*)a + size) != *((char*)b + size))
			return -1;
	return 0;
}

/**
 * Returns first PRL entry for given IPv6 address
 **/
struct PRLENTRY* find_internal_pdr_by_addr6(struct in6_addr *addr) {
	struct PRLENTRY* cur = prl_head;
	while (cur) {
		if (mycmp(&cur->addr6.sin6_addr, addr, sizeof(struct in6_addr)) == 0) 
			return cur;
		cur = cur->next;
	}
	return NULL;
}





/**
 * Return 0 if IPv4 address is global
 * Return 1 if IPv4 Address is private
 **/
static int ipv4_is_private(uint32_t addr) {
	/* TODO: Is this LITTLE_ENDIAN/BIG_ENDIAN save? */
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
	}
	/* Not private */
	return 0;
}


/**
 * Resolves one router name and appends the found IPv4 Addresses
 * to internal PRL
 **/
int add_router_name_to_internal_prl(const char* host, int default_timeout)
{
	struct addrinfo *addr_info, *p, hints;
	int err;

	if (host == NULL)
		return -1;

	/* Get addresses for host */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	/* strictly speaking this should be IPPROTO_IPV6 to return IPv4 addresses
	   that are suitable for IPv6 in IPv4 tunnelling. This however fails on my
	   android 4.2.2 device and returns an empty list. Because we only care about
	   the IPv4 address, do our tunnel magic later, we might as well fail later
	   and request an IPv4 address for UDP, which should work on all systems. */
	hints.ai_protocol=IPPROTO_UDP;
	err = getaddrinfo(host, NULL, &hints, &addr_info);

	if (err) {
		if (verbose >= 0)
			syslog(LOG_WARNING, "add_router_name_to_internal_prl: %s: %s\n", host, gai_strerror(err));
		/* host not found is not yet fatal */
		return 0;
	}

	p=addr_info;
	while (p)
	{
		struct in_addr addr;
		struct PRLENTRY* pr;
		
		addr = ((struct sockaddr_in*)(p->ai_addr))->sin_addr;
		pr = find_internal_pdr_by_addr(addr.s_addr);
		if (!pr) { /* not yet in PRL */
			if (verbose >= 1)
				syslog(LOG_INFO, "Adding internal PDR %s\n", inet_ntoa(addr));
			/* Add local address (not always RFC conform) */
			pr=new_internal_pdr();
			pr->ip = addr.s_addr;
			pr->default_timeout = default_timeout;
			pr->addr6.sin6_addr.s6_addr32[0] = htonl(0xfe800000);
			pr->addr6.sin6_addr.s6_addr32[1] = htonl(0x00000000);
			pr->addr6.sin6_addr.s6_addr32[2] = htonl(0x00005efe);
			pr->addr6.sin6_addr.s6_addr32[3] = addr.s_addr;
			
			add_internal_pdr(pr);
			
			/* Add RFC conform global address as well, if saddr is public */
			if (!ipv4_is_private(addr.s_addr)) {
				/* link siblings */
				pr->sibling = new_internal_pdr();
				pr->sibling->sibling = pr;
				pr=pr->sibling;
				
				pr->ip = addr.s_addr;
				pr->default_timeout = default_timeout;
				pr->addr6.sin6_addr.s6_addr32[0] = htonl(0xfe800000);
				pr->addr6.sin6_addr.s6_addr32[1] = htonl(0x00000000);
				pr->addr6.sin6_addr.s6_addr32[2] = htonl(0x02005efe);
				pr->addr6.sin6_addr.s6_addr32[3] = addr.s_addr;

				add_internal_pdr(pr);
			}
		} else { /* stale/duplicate entry already in PRL */
			if (verbose >=2)
				syslog(LOG_INFO, "%s internal PDR %s\n",
					pr->stale?"Refreshing":"Ignoring duplicate",
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

/**
 * Removes all stale entries from kernel
 * (needs root privileges)
 **/
int prune_kernel_prl(const char *dev) {
	struct PRLENTRY* pr;
	
	pr=get_first_internal_pdr();
	while (pr) {
		if (pr->stale) {
			struct in_addr addr;
			addr.s_addr = pr->ip;
			if (verbose >= 1)
				syslog(LOG_INFO, "Removing old PDR %s from kernel\n", inet_ntoa(addr));
			
			tunnel_del_prl(dev, pr->ip);
			pr = del_internal_pdr(pr);
		} else 
			pr = pr->next;
	}
  
	return 0;
}


int drop_to_user(char* username)
{
	struct passwd *pw = getpwnam (username);
	if (pw == NULL)
	{
		syslog(LOG_ERR, "User \"%s\": %s\n", username,
			errno ? strerror (errno) : "User not found");
		return -1;
	}
  
	/* Drop privileges */
	if (setgid(pw->pw_gid) < 0)
		return -1;
	if (initgroups(username, pw->pw_gid) < 0)
		return -1;
	if (setuid(pw->pw_uid) < 0)
		return -1;
	
	return 0;
}

/**
 * SIGHUP
 **/
static void sighup_handler_child() {
	exit(EXIT_CHECK_PRL);
}


/**
 * Drops privileges after creating sockets
 * Add PRL to kernel
 * Loop and send RS
 * 
 * Returns:
 *   EXIT_ERROR_FATAL
 *   EXIT_ERROR_LAYER2
 *   EXIT_CHECK_PRL
 */
int run_solicitation_loop(char* tunnel_name, int check_dns_timeout, char* username) {
	struct PRLENTRY* pr;
	int fd;
	int ifindex;
	int check_dns;

	srand((unsigned int)time(NULL));

	ifindex = if_nametoindex(tunnel_name);
	if (ifindex < 0) {
		syslog(LOG_ERR, "if_nametoindex: %s\n", strerror(errno));
		return EXIT_ERROR_FATAL;
	}

	/* Add internal PRL to kernel PRL */
	pr = get_first_internal_pdr();
	if (pr == NULL) {
		if (verbose >= -2)
			syslog(LOG_ERR, "PRL empty!\n");
		return EXIT_ERROR_FATAL;
	}
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
	
	/* Create a socket for sending router solicitations
	   This socket is created with root privileges and will keep those
	   even after dropping to 'nobody' */
	fd = create_rs_socket();
	if (fd < 0) {
		if (verbose >= -2)
			syslog(LOG_ERR, "create_rs_socket: invalid fd: %s\n", strerror(errno));
		return EXIT_ERROR_FATAL;
	}

	/* Drop root privileges! */
	if (drop_to_user(username) < 0)
		return EXIT_ERROR_FATAL;

	signal(SIGTERM, SIG_IGN);
	signal(SIGINT, SIG_IGN);
	signal(SIGHUP, sighup_handler_child);

	check_dns = (check_dns_timeout > 0);

	while (!check_dns || check_dns_timeout > 0) {
		fd_set fds;
		struct timeval timeout;
		int ret;
		int next_timeout;
		
		/* Find smallest timeout value */
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

		/* Wait for timeout or data */
		ret = select(fd+1, &fds, NULL, NULL, &timeout);
		if (ret < 0) {
			close(fd);
			syslog(LOG_ERR, "select: %s\n", strerror(errno));
			return EXIT_ERROR_FATAL;
		}
		
		if (ret && (FD_ISSET(fd, &fds))) {
			/* Data available on socket */
			
			/* Calculate the passed time till data was available*/
			next_timeout -= (timeout.tv_sec * 1000 + timeout.tv_usec / 1000);
			
			/* Receive and parse RA */
			if (recvadv(fd, ifindex) < 0) {
				syslog(LOG_ERR, "recvadv: %s\n", strerror(errno));
				return EXIT_ERROR_LAYER2;
			}
		}
		if (check_dns)
			check_dns_timeout -= next_timeout;

		/* Decrease timeout of all PRL entries and send a solicitation, if necessary */
		pr = get_first_internal_pdr();
		while (pr) {
			pr->next_timeout -= next_timeout;
			if (pr->next_timeout <= 0) {
				if (verbose >= 1) {
					char addrstr[INET6_ADDRSTRLEN];
					syslog(LOG_INFO, "Soliciting %s\n",
					       inet_ntop(AF_INET6,
							 &pr->addr6.sin6_addr,
							 addrstr,
							 sizeof(addrstr)));
				}
				if (send_rdisc(fd, ifindex, &pr->addr6.sin6_addr) < 0) {
					if (verbose >= -1) {
						syslog(LOG_ERR, "send_rdisc: %s\n", strerror(errno));
					}
					return EXIT_ERROR_LAYER2;
				}

				pr->rs_sent++;
				if (pr->rs_sent >= MAX_RTR_SOLICITATIONS) {
					pr->rs_sent = 0;
					pr->next_timeout += DEFAULT_MINROUTERSOLICITINTERVAL * 1000;
				} else
					pr->next_timeout += RTR_SOLICITATION_INTERVAL * 1000;
			}
			pr = pr->next;
		}
	}
	close(fd);
	return EXIT_CHECK_PRL;
}

