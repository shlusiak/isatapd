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
#include <fcntl.h>
#include <syslog.h>
#include <errno.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>


#define _GNU_SOURCE
#include <getopt.h>

#ifdef HAVE_CONFIG_H
	#include "config.h"
#endif

#include "tunnel.h"
#include "rdisc.h"
#include "isatap.h"
#include "prl.h"


#define DEFAULT_ROUTER_NAME "isatap"
#define WAIT_FOR_LINK (15)  /* seconds between polling, if link is down */


static char* tunnel_name = NULL;
static char* interface_name = NULL;


struct ROUTER_NAME {
	char* name;
	struct ROUTER_NAME* next;
} *router_name = NULL;

static int   rs_interval = 600;
       int   verbose = 0;
static int   daemonize = 0;
static char* pid_file = NULL;
static int   ttl = 64;
static int   mtu = 0;
static int   pmtudisc = 1;
static int   volatile go_down = 0;
static pid_t child = 0;

static int   syslog_facility = LOG_DAEMON;



static void sigint_handler(int sig)
{
	signal(sig, SIG_DFL);
	if (verbose >= 0)
		syslog(LOG_NOTICE, "signal %d received, going down.\n", sig);
	if (child)
		kill(child, SIGTERM);
	go_down = 1;
}

static void sighup_handler(int sig)
{
	if (verbose >= 0)
		syslog(LOG_NOTICE, "SIGHUP received.\n");
	if (child)
		kill(child, SIGTERM);
}



static void show_help()
{
	fprintf(stderr, "Usage: isatapd [OPTIONS] [ROUTER]...\n");
	fprintf(stderr, "       -n --name       name of the tunnel\n");
	fprintf(stderr, "                       default: is0\n");
	fprintf(stderr, "       -l --link       tunnel link device\n");
	fprintf(stderr, "                       default: auto\n");
	fprintf(stderr, "          --mtu        set tunnel MTU\n");
	fprintf(stderr, "                       default: auto\n");
	fprintf(stderr, "          --ttl        set tunnel hoplimit.\n");
	fprintf(stderr, "                       default: %d\n", ttl);
	fprintf(stderr, "          --nopmtudisc disable ipv4 pmtu discovery.\n");
	fprintf(stderr, "                       default: pmtudisc enabled\n");
	fprintf(stderr, "\n");

	fprintf(stderr, "       -r --router     set potential router.\n");
	fprintf(stderr, "                       default: '%s'.\n", DEFAULT_ROUTER_NAME);
	
	fprintf(stderr, "       -i --interval   interval to check PRL and perform router solicitation\n");
	fprintf(stderr, "                       default: %d seconds\n", rs_interval);
	fprintf(stderr, "\n");

	fprintf(stderr, "       -d --daemon     fork into background\n");
	fprintf(stderr, "       -p --pid        store pid of daemon in file\n");
	fprintf(stderr, "       -1 --one-shot   only set up tunnel and PRL, then exit\n");
	fprintf(stderr, "\n");

	fprintf(stderr, "       -v --verbose    increase verbosity\n");
	fprintf(stderr, "       -q --quiet      decrease verbosity\n");
	fprintf(stderr, "\n");

	fprintf(stderr, "       -h --help       display this message\n");
	fprintf(stderr, "          --version    display version\n");

	exit(1);
}

static void show_version()
{
	fprintf(stderr, PACKAGE "-" VERSION "\n\n");
	fprintf(stderr, "Copyright (c) 2009 Sascha Hlusiak <mail@saschahlusiak.de>\n");
	fprintf(stderr, "\nThis is free software; You may redistribute copies of this software\n");
	fprintf(stderr, "under the terms of the GNU General Public License.\n");
	fprintf(stderr, "For more information about these matters, see the file named COPYING.\n");

	exit(0);
}

/**
 * Adds a router name to the linked list of router names
 **/
static void add_router_name(const char* name)
{
	struct ROUTER_NAME *n;
	n = (struct ROUTER_NAME*)malloc(sizeof(struct ROUTER_NAME));
	n->next = router_name;
	router_name = n;
	n->name = strdup(name);
}

static void parse_options(int argc, char** argv)
{
	int c;
	const char* short_options = "hn:i:r:vqd1l:p:";
	struct option long_options[] = {
		{"help", 0, NULL, 'h'},
		{"name", 1, NULL, 'n'},
		{"link", 1, NULL, 'l'},
		{"router", 1, NULL, 'r'},
		{"interval", 1, NULL, 'i'},
		{"verbose", 0, NULL, 'v'},
		{"quiet", 0, NULL, 'q'},
		{"daemon", 0, NULL, 'd'},
		{"one-shot", 0, NULL, '1'},
		{"version", 0, NULL, 'V'},
		{"mtu", 1, NULL, 'm'},
		{"pid", 1, NULL, 'p'},
		{"ttl", 1, NULL, 't'},
		{"nopmtudisc", 0, NULL, 'P'},
		{NULL, 0, NULL, 0}
	};
	int long_index = 0;

	while (1) {
		c = getopt_long(argc, argv, short_options, long_options, &long_index);
		if (c == -1) break;

		switch (c) {
		case 'n': if (optarg)
				tunnel_name = strdup(optarg);
			break;
		case 'l': if (optarg)
				interface_name = strdup(optarg);
			break;
		case 'r': if (optarg)
				add_router_name(optarg);
			break;
		case 'i': if (optarg) {
				rs_interval = atoi(optarg);
				if (rs_interval <= 0) {
					syslog(LOG_ERR, "invalid cardinal -- %s\n", optarg);
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
		case 'p': pid_file = strdup(optarg);
			break;
		case '1': daemonize = 2;
			break;
		case 'm': mtu = atoi(optarg);
			if (mtu <= 0) {
				syslog(LOG_ERR, "invalid mtu -- %s\n", optarg);
				show_help();
			}
			break;
		case 't': if ((strcmp(optarg, "auto") == 0) || (strcmp(optarg, "inherit") == 0))
				ttl = 0;
			else {
				ttl = atoi(optarg);
				if (ttl <= 0 || ttl > 255) {
					syslog(LOG_ERR, "invalid ttl -- %s\n", optarg);
					show_help();
				}
			}
			break;
		case 'P': pmtudisc = 0;
			break;

		case 'V': show_version();
			break;

		default:
			syslog(LOG_ERR, "not implemented option -- %s\n", argv[optind-1]);
		case 'h':
		case '?':
			show_help();
			break;
		}
	}

	for (; optind < argc; optind++)
		add_router_name(argv[optind]);
	if (router_name == NULL)
		add_router_name(DEFAULT_ROUTER_NAME);
}




/**
 * Fills the linked list of PRL entries with IPs
 * derived from router names (DNS)
 **/
static int fillPRL()
{
	struct ROUTER_NAME* r;
	flushPRL();
	r = router_name;
	while (r) {
		if (add_router_name_to_prl(r->name, rs_interval) < 0)
			return -1;
		r = r->next;
	}
	return 0;
}

/**
 * Gets source IPv4 Address of tunnel
 * Either IP address of interface
 * or outgoing IPv4 address
 **/
static uint32_t get_tunnel_saddr(const char* iface)
{
	uint32_t saddr;
	struct PRLENTRY* pr;

	if (iface)
		return get_if_addr(iface);

	pr = getFirstPR();
	saddr = 0;

	while (pr) {
		struct sockaddr_in addr, addr2;
		socklen_t addrlen;
		int fd = socket (AF_INET, SOCK_DGRAM, 0);
	
		if (fd < 0)
			break;

		addr.sin_family = AF_INET;
		addr.sin_port = 0;
		addr.sin_addr.s_addr = pr->ip;
		if (connect (fd, (struct sockaddr*)&addr, sizeof(struct sockaddr_in))== 0) {
			addrlen = sizeof(addr2);
			getsockname(fd, (struct sockaddr *)&addr2, &addrlen);
			if (addrlen == sizeof(addr2)) {
				if (saddr == 0)
					saddr = addr2.sin_addr.s_addr;
				else if (saddr != addr2.sin_addr.s_addr) {
					syslog(LOG_WARNING,
						"Different outgoing interfaces for PDR %s. Ignoring.\n",
						inet_ntoa(addr.sin_addr));
					pr = delPR(pr);
					close(fd);
					continue;
				}
			}
		} else  {
			syslog(LOG_WARNING, "PDR %s unreachable. Not removing.\n",
						inet_ntoa(addr.sin_addr));
// 			pr = delPR(pr);
// 			close(fd);
// 			continue;
		}
		close (fd);
	
		pr = pr->next;
	}
	return saddr;
}

/**
 * Wait until get_tunnel_saddr is successful and return source address
 **/
static uint32_t wait_for_link()
{
	uint32_t saddr;
	if ((saddr = get_tunnel_saddr(interface_name)) == 0) {
		if (verbose >= 0) {
			if (interface_name)
				syslog(LOG_INFO, "waiting for link %s to become ready...\n", interface_name);
			else
				syslog(LOG_INFO, "waiting for router %s to become reachable...\n", router_name->name);
		}

		do {
			if (verbose >= 2) {
				syslog(LOG_DEBUG, "still waiting for link...\n");
			}
			sleep(WAIT_FOR_LINK);
			if (go_down)
				return 0;
			saddr = get_tunnel_saddr(interface_name);
		} while ((go_down == 0) && (saddr == 0));

		if (verbose >= 0) {
			if (saddr) {
				if (interface_name)
					syslog(LOG_INFO, "link %s became ready...\n", interface_name);
				else
					syslog(LOG_INFO, "router %s became reachable...\n", router_name->name);
			}
		}
	}
	return saddr;
}


static uint32_t start_isatap(uint32_t saddr)
{
	if (saddr == 0) {
		if (verbose >= -1)
			syslog(LOG_ERR, "get_if_addr: %s\n", strerror(errno));
		exit(1);
	}

	if (tunnel_add(tunnel_name, interface_name, saddr, ttl, pmtudisc) < 0) {
		if (verbose >= -1)
			syslog(LOG_ERR, "tunnel_add: %s\n", strerror(errno));
		exit(1);
	}

	if (verbose >= 1) {
		struct in_addr addr;
		addr.s_addr = saddr;
		syslog(LOG_INFO, "%s created (local %s, %s)\n", tunnel_name, inet_ntoa(addr), pmtudisc?"pmtudisc":"nopmtudisc");
	}

	if (mtu > 0) {
		if (tunnel_set_mtu(tunnel_name, mtu) < 0) {
			if (verbose >= -1)
				syslog(LOG_ERR, "tunnel_set_mtu: %s\n", strerror(errno));
			tunnel_del(tunnel_name);
			exit(1);
		}
	}

	if (tunnel_up(tunnel_name) < 0) {
		if (verbose >= -1)
			syslog(LOG_ERR, "tunnel_up: %s\n", strerror(errno));
		tunnel_del(tunnel_name);
		exit(1);
	}
	if (verbose >= 0)
		syslog(LOG_NOTICE, "interface %s up\n", tunnel_name);

	return saddr;
}

static void stop_isatap()
{
	if (tunnel_down(tunnel_name) < 0) {
		if (verbose >= -1)
			syslog(LOG_ERR, "tunnel_down: %s\n", strerror(errno));
	} else if (verbose >= 0)
		syslog(LOG_NOTICE, "interface %s down\n", tunnel_name);
	
	if (tunnel_del(tunnel_name) < 0) {
		if (verbose >= -1)
			syslog(LOG_ERR, "tunnel_del: %s\n", strerror(errno));
	} else if (verbose >= 1)
		syslog(LOG_INFO, "%s deleted\n", tunnel_name);
}

static void write_pid_file()
{
	struct flock fl;
	char s[32];
	int pf;

	pf = open(pid_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (pf < 0) {
		syslog(LOG_ERR, "Cannot create pid file, terminating: %s\n", strerror(errno));
		exit(1);
	}
	snprintf(s, sizeof(s), "%d\n", (int)getpid());
	if (write(pf, s, strlen(s)) < strlen(s))
		syslog(LOG_ERR, "write: %s\n", strerror(errno));
	if (fsync(pf) < 0)
		syslog(LOG_ERR, "fsync: %s\n", strerror(errno));

	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 0;

	if (fcntl(pf, F_SETLK, &fl) < 0) {
		syslog(LOG_ERR, "Cannot lock pid file, terminating: %s\n", strerror(errno));
		exit(1);
	}
}





int main(int argc, char **argv)
{
	uint32_t saddr;

	openlog(NULL, LOG_PID | LOG_PERROR, syslog_facility);
	parse_options(argc, argv);

	if (tunnel_name == NULL) {
		if (interface_name) {
			tunnel_name = (char *)malloc(strlen(interface_name)+3+1);
			strcpy(tunnel_name, "is_");
			strcat(tunnel_name, interface_name);
		} else tunnel_name = strdup("is0");
	}

	if (strchr(tunnel_name, ':')) {
		syslog(LOG_ERR, "no ':' in tunnel name: %s!\n", tunnel_name);
		exit(1);
	}
	if (pmtudisc == 0 && ttl) {
		syslog(LOG_ERR, "--nopmtudisc depends on --ttl inherit!\n");
		exit(1);
	}

	if (daemonize == 1) {
		pid_t pid;

		pid = fork();
		if (pid < 0) {
			syslog(LOG_ERR, "fork: %s\n", strerror(errno));
			exit(1);
		}
		if (pid > 0) {
			/* Server */
			if (verbose >= 1)
				fprintf(stderr, PACKAGE ": running isatap daemon as pid %d\n",(int)pid);
			exit(0);
		}
		/* Client */
	}
	if (daemonize == 2) {
		saddr = get_tunnel_saddr(interface_name);
		if (saddr == 0) {
			if (interface_name == NULL)
				fprintf(stderr, PACKAGE ": router %s unreachable...\n", router_name->name);
			else
				perror("get_tunnel_saddr");
			exit(1);
		}
		saddr = start_isatap(saddr);
		if (saddr == 0)
			perror("start_isatap");
		fillPRL();
		/* one-shot, exit program when done */
		exit(0);
	}
	
	if (pid_file != NULL)
		write_pid_file();

	if (daemonize == 1) {
		setsid();
		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		close(STDERR_FILENO);
	}

	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);
	signal(SIGHUP, sighup_handler);


	fillPRL();
	saddr = wait_for_link();
	if (!go_down)
	{
		saddr = start_isatap(saddr);
		while (!go_down)
		{
			uint32_t saddr_n;
			child = fork();
			if (child < 0) {
				perror("fork:");
				break;
			}
			if (child) {
				int status;
				waitpid(child, &status, 0);
				if (verbose >= 1)
					syslog(LOG_INFO, "Solicitation Loop exited with status %d\n", status);
				child = 0;
			} else {
				int status;
				signal(SIGTERM, SIG_DFL);
				signal(SIGINT, SIG_IGN);
				signal(SIGHUP, SIG_IGN);
	
				status = run_solicitation_loop(tunnel_name);
				closelog();
				exit(status);
			}
			fillPRL();
			saddr_n = wait_for_link();
			if (go_down)
				break;
	
			if (saddr_n != saddr) {
				syslog(LOG_WARNING, "Link change detected. Re-creating tunnel.\n");
				stop_isatap();
				saddr = start_isatap(saddr_n);
			}
		}
		stop_isatap();
	}

 	if (pid_file) {
		if (unlink(pid_file) < 0)
			syslog(LOG_WARNING, "cannot unlink pid file: %s\n", strerror(errno));
	}
	closelog();

	return 0;
}
