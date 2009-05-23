/*
 * isatapd.c    main
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
#include <sys/types.h>
#include <signal.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#define _GNU_SOURCE
#include <getopt.h>

#ifdef HAVE_CONFIG_H
	#include "config.h"
#endif

#include "tunnel.h"
#include "rdisc.h"


static char* tunnel_name = NULL;
static char* interface_name = NULL;
static char* router_name[10] = { "isatap", NULL };
static int   router_num = 0;
static int   probe_interval = 600;
static int   verbose = 0;
static int   daemonize = 0;
static int volatile go_down = 0;

void show_help()
{
	fprintf(stderr, "Usage: isatapd [OPTIONS] interface...\n");
	fprintf(stderr, "       -h --help       display this message\n");
	fprintf(stderr, "       -n --name       name of the tunnel\n");
	fprintf(stderr, "                       default: auto\n");
	fprintf(stderr, "       -r --router     a potential router (up to 10).\n");
	fprintf(stderr, "                       default: '%s'.\n", router_name[0]);
	fprintf(stderr, "       -i --interval   interval to check PRL and perform router solicitation\n");
	fprintf(stderr, "                       default: %d seconds\n", probe_interval);
	fprintf(stderr, "       -d --daemon     fork into background\n");
	fprintf(stderr, "       -v --verbose    increase verbosity\n");
	fprintf(stderr, "       -q --quiet      decrease verbosity\n");
	fprintf(stderr, "          --version    display version\n");
	fprintf(stderr, "       interface       tunnel link device\n");

	exit(0);
}

void show_version()
{
	fprintf(stderr, PACKAGE "-" VERSION "\n\n");
	fprintf(stderr, "Copyright (c) 2009 Sascha Hlusiak\n");
	fprintf(stderr, "\nThis is free software; You may redistribute copies of this software\n");
	fprintf(stderr, "under the terms of the GNU General Public License.\n");
	fprintf(stderr, "For more information about these matters, see the file named COPYING.\n");

	exit(0);
}

void parse_options(int argc, char** argv)
{
	int c;
	const char* short_options = "hn:i:r:vqd";
	struct option long_options[] = {
		{"help", 0, NULL, 'h'},
		{"name", 1, NULL, 'n'},
		{"router", 1, NULL, 'r'},
		{"interval", 1, NULL, 'i'},
		{"verbose", 0, NULL, 'v'},
		{"quiet", 0, NULL, 'q'},
		{"daemon", 0, NULL, 'd'},
		{"version", 0, NULL, 'V'},
		{NULL, 0, NULL, 0}
	};
	int long_index = 0;

	while (1) {
		c = getopt_long(argc, argv, short_options, long_options, &long_index);
		if (c == -1) break;

		switch (c) {
		case 'h': show_help();
			break;
		case 'n': if (optarg)
				tunnel_name = strdup(optarg);
			break;
		case 'r': if (optarg) {
				if (router_num < sizeof(router_name)/sizeof(router_name[0]))
					router_name[router_num++] = strdup(optarg);
				else {
					fprintf(stderr, "%s: too many default routers\n", argv[0]);
					show_help();
				}
			}
			break;
		case 'i': if (optarg) {
				probe_interval = atoi(optarg);
				if (probe_interval <= 0) {
					fprintf(stderr, "%s: invalid cardinal -- %s\n", argv[0], optarg);
					show_help();
				}
			}
			break;
		case 'v': verbose++;
			break;
		case 'q': verbose--;
			break;
		case 'd': daemonize = 1;
			break;

		case 'V': show_version();
			break;
		default:
			fprintf(stderr, "%s: not implemented option -- %s\n", argv[0], argv[optind-1]);
		case '?':
			show_help();
			break;
		}
	}

	if (optind == argc-1) {
		interface_name = strdup(argv[optind]);
	} else {
		fprintf(stderr, "%s: missing argument -- interface\n", argv[0]);
		show_help();
	}
}


int add_prl_entry(const char* host)
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
			fprintf(stderr, "getaddrinfo: %s: %s\n", host, gai_strerror(err));
		return 0;
	}

	p=addr_info;
	while (p)
	{
		struct in_addr addr;
		struct in6_addr addr6;
		addr = ((struct sockaddr_in*)(p->ai_addr))->sin_addr;
		if (verbose >= 1)
			printf("Adding PDR %s\n", inet_ntoa(addr));

		if (tunnel_add_prl(tunnel_name, addr.s_addr, 1) < 0) {
			if (verbose >= 2)
				perror("tunnel_add_prl");
		}
		
		addr6.s6_addr32[0] = htonl(0xfe800000);
		addr6.s6_addr32[1] = htonl(0x00000000);
		addr6.s6_addr32[2] = htonl(0x00005efe);
		addr6.s6_addr32[3] = addr.s_addr;

		if (send_rdisc(tunnel_name, &addr6) < 0) {
			if (verbose >= -1) {
				perror("send_rdisc");
			}
			freeaddrinfo(addr_info);
			return -1;
		}

		addr6.s6_addr32[0] = htonl(0xfe800000);
		addr6.s6_addr32[1] = htonl(0x00000000);
		addr6.s6_addr32[2] = htonl(0x02005efe);
		addr6.s6_addr32[3] = addr.s_addr;

		if (send_rdisc(tunnel_name, &addr6) < 0) {
			if (verbose >= -1) {
				perror("send_rdisc");
			}
			freeaddrinfo(addr_info);
			return -1;
		}

		p=p->ai_next;
	}	
	freeaddrinfo(addr_info);

	return 0;
}

void sigint_handler(int sig)
{
	signal(sig, SIG_DFL);
	if (verbose >= 0)
		fprintf(stderr, "signal %d received, going down.\n", sig);
	go_down = 1;
}

void sighup_handler(int sig)
{
}

void add_prl(int sig)
{
	int i;
	for (i = 0; i < sizeof(router_name)/sizeof(router_name[0]); i++)
		 if (router_name[i])
	{
		if (add_prl_entry(router_name[i]) < 0) {
			return;
		}
	}

	alarm(probe_interval);
}


static uint32_t start_isatap()
{
	uint32_t saddr;

	saddr = get_if_addr(interface_name);
	if (saddr == 0) {
		if (verbose >= -1)
			perror("get_if_addr");
		exit(1);
	}
	
	if (tunnel_add(tunnel_name, interface_name, saddr) < 0) {
		if (verbose >= -1)
			perror("tunnel_add");
		exit(1);
	}

	if (verbose >= 1)
		printf("%s created (%s, 0x%08X)\n", tunnel_name, interface_name, ntohl(saddr));

	if (tunnel_up(tunnel_name) < 0) {
		if (verbose >= -1)
			perror("tunnel_up");
		tunnel_del(tunnel_name);
		exit(1);
	}
	if (verbose >= 2)
		printf("%s up\n", tunnel_name);

	return saddr;
}

static void stop_isatap()
{
	if (tunnel_down(tunnel_name) < 0) {
		if (verbose >= -1)
			perror("tunnel_down");
	} else if (verbose >= 2)
		printf("%s down\n", tunnel_name);
	
	if (tunnel_del(tunnel_name) < 0) {
		if (verbose >= -1)
			perror("tunnel_del");
	} else if (verbose >= 1)
		printf("%s deleted\n", tunnel_name);
}



int main(int argc, char **argv)
{
	uint32_t saddr;

	parse_options(argc, argv);

	if (tunnel_name == NULL) {
		tunnel_name = (char *)malloc(strlen(interface_name)+3+1);
		strcpy(tunnel_name, "is_");
		strcat(tunnel_name, interface_name);
	}

	if (daemonize) {
		pid_t pid;
		pid = fork();
		if (pid < 0) {
			perror("fork");
			exit(1);
		}
		if (pid > 0) { /* Server */
			if (verbose >= 0)
				fprintf(stderr, "%s: running isatap daemon on interface %s\n", argv[0], interface_name);
			exit(0);
		}
		setsid();
		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		close(STDERR_FILENO);
	}

	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);
	signal(SIGALRM, add_prl);
	signal(SIGHUP, sighup_handler);

	while (!go_down)
	{
		while ((get_if_addr(interface_name) == 0) && (!go_down)) {
			if (verbose >= 0)
				fprintf(stderr, "%s: link %s not ready...\n", argv[0], interface_name);
			sleep(5);
		}
		if (go_down)
			break;

		saddr = start_isatap();
		add_prl(SIGALRM);

		while (!go_down) {
			pause();
			if (get_if_addr(interface_name) != saddr) {
				alarm(0);
				if (verbose >= 0)
					fprintf(stderr, "%s: address of %s changed\n", argv[0], interface_name);
				saddr = 0;
				break;
			} else if (!go_down)
				add_prl(SIGALRM);
		}
		stop_isatap();
	}

	return 0;
}
