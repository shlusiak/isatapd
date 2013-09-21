/*
 * main.c       main
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
#include <net/if.h>
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


static char* tunnel_name = NULL;
static char* interface_name = NULL;

/**
 * DNS Names or IPv4 Addresses of possible routers
 * to be resolved later
 **/
static struct ROUTER_NAME {
	char* name;
	struct ROUTER_NAME* next;
} *router_name = NULL;

static int   rs_interval = 65536;
static int   dns_interval = DEFAULT_PRLREFRESHINTERVAL;
       int   verbose = 0;
static int   daemonize = 0;
static char* pid_file = NULL;
static int   ttl = DEFAULT_TTL;
static int   mtu = DEFAULT_MTU;
static int   pmtudisc = 1;
static int   volatile go_down = 0;
static pid_t child = 0;
static char* unpriv_username = DEFAULT_UNPRIV_USERNAME;

static int   syslog_facility = LOG_DAEMON;






static void show_help()
{
	fprintf(stderr, "Usage: isatapd [OPTIONS] [ROUTER]...\n");
	fprintf(stderr, "       -n --name       name of the tunnel\n");
	fprintf(stderr, "                       default: is0\n");
	fprintf(stderr, "       -l --link       tunnel link device\n");
	fprintf(stderr, "                       default: auto\n");
	fprintf(stderr, "       -m --mtu        set tunnel MTU\n");
	fprintf(stderr, "                       default: auto\n");
	fprintf(stderr, "       -t --ttl        set tunnel hoplimit.\n");
	fprintf(stderr, "                       default: %d\n", DEFAULT_TTL);
	fprintf(stderr, "       -N --nopmtudisc disable ipv4 pmtu discovery.\n");
	fprintf(stderr, "                       default: pmtudisc enabled\n");
	fprintf(stderr, "\n");

	fprintf(stderr, "       -r --router     set potential router.\n");
	fprintf(stderr, "                       default: '%s'.\n", DEFAULT_ROUTER_NAME);
	
	fprintf(stderr, "       -i --interval   interval to perform router solicitation\n");
	fprintf(stderr, "                       default: auto\n");
	fprintf(stderr, "       -D --check-dns  interval to perform DNS resolution and\n");
	fprintf(stderr, "                       recreate PRL.\n");
	fprintf(stderr, "                       default: %d seconds\n", DEFAULT_PRLREFRESHINTERVAL);
	fprintf(stderr, "\n");

	fprintf(stderr, "       -d --daemon     fork into background\n");
	fprintf(stderr, "       -p --pid        store pid of daemon in file\n");
	fprintf(stderr, "          --user       drop privileges to this user\n");
	fprintf(stderr, "                       default: '%s'\n", DEFAULT_UNPRIV_USERNAME);
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
static void add_router_to_name_list(const char* name)
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
	const char* short_options = "hn:i:r:vqd1l:p:m:t:ND:";
	struct option long_options[] = {
		{"help", 0, NULL, 'h'},
		{"name", 1, NULL, 'n'},
		{"link", 1, NULL, 'l'},
		{"router", 1, NULL, 'r'},
		{"interval", 1, NULL, 'i'},
		{"check-dns", 1, NULL, 'D'},
		{"verbose", 0, NULL, 'v'},
		{"quiet", 0, NULL, 'q'},
		{"daemon", 0, NULL, 'd'},
		{"version", 0, NULL, 'V'},
		{"mtu", 1, NULL, 'm'},
		{"pid", 1, NULL, 'p'},
		{"ttl", 1, NULL, 't'},
		{"nopmtudisc", 0, NULL, 'N'},
		{"user", 1, NULL, 'U'},
		{NULL, 0, NULL, 0}
	};
	int long_index = 0;

	while (1) {
		c = getopt_long(argc, argv, short_options, long_options, &long_index);
		if (c == -1) break;

		switch (c) {
		  /* --name */
		case 'n': if (optarg && strcmp("auto", optarg))
				tunnel_name = strdup(optarg);
			break;
			
		  /* --link */
		case 'l': if (optarg && strcmp("auto", optarg))
				interface_name = strdup(optarg);
			break;
			
		  /* --router */
		case 'r': if (optarg)
				add_router_to_name_list(optarg);
			break;
			
		  /* --interval */
		case 'i': if (optarg && strcmp("auto", optarg)) {
				if ((sscanf(optarg, "%d", &rs_interval) < 1) || (rs_interval < 0)) {
					syslog(LOG_ERR, "invalid cardinal -- %s\n", optarg);
					show_help();
				}
				if (rs_interval < DEFAULT_MINROUTERSOLICITINTERVAL) {
					syslog(LOG_ERR, "interval must be greater than %d sec\n", 
						DEFAULT_MINROUTERSOLICITINTERVAL);
					show_help();
				}
			}
			break;
			
		  /* --check-dns */
		case 'D': if (optarg) {
				if ((sscanf(optarg, "%d", &dns_interval) < 1) || (dns_interval < 0)) {
					syslog(LOG_ERR, "invalid cardinal -- %s\n", optarg);
					show_help();
				}
				if (dns_interval != 0 && dns_interval < DEFAULT_MINROUTERSOLICITINTERVAL) {
					syslog(LOG_ERR, "dns-check interval must be greater than %d sec\n", DEFAULT_MINROUTERSOLICITINTERVAL);
					show_help();
				}
			}
			break;
			
		  /* --mtu */
		case 'm': if ((strcmp(optarg, "auto") == 0) || (strcmp(optarg, "0") == 0))
				mtu = 0;
			else {
				mtu = atoi(optarg);
				if (mtu <= 0) {
					syslog(LOG_ERR, "invalid mtu -- %s\n", optarg);
					show_help();
				}
			}
			break;
		  /* --ttl */
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
		  /* --nopmtudisc */
		case 'N': pmtudisc = 0;
			break;
			
		  /* --daemonize */
		case 'd': daemonize = 1;
			break;
		  /* --pid */
		case 'p': pid_file = strdup(optarg);
			break;
		  /* --user */
		case 'U': unpriv_username = strdup(optarg);
			break;

		  /* --verbose */
		case 'v': verbose++;
			break;
		  /* --quiet */
		case 'q': verbose--;
			break;

		  /* --version */
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
		add_router_to_name_list(argv[optind]);
	if (router_name == NULL)
		add_router_to_name_list(DEFAULT_ROUTER_NAME);
	
	if (tunnel_name == NULL)
		tunnel_name = strdup(DEFAULT_TUNNEL_NAME);
	if (strchr(tunnel_name, ':')) {
		syslog(LOG_ERR, "no ':' in tunnel name: %s!\n", tunnel_name);
		exit(1);
	}
	if (pmtudisc == 0 && ttl) {
		syslog(LOG_ERR, "--nopmtudisc depends on --ttl inherit!\n");
		exit(1);
	}
}




/**
 * Fills the linked list of PRL entries with IPs
 * derived from router names (DNS)
 * Return 0 when success
 **/
static int fill_internal_prl()
{
	struct ROUTER_NAME* r;
	struct PRLENTRY *e;
	
	/* Mark all existing PRL entries as 'stale' */
	e=get_first_internal_pdr();
	while (e) {
		e->stale = 1;
		e=e->next;
	}
	
	r = router_name;
	while (r) {
		/* Resolv single entry and add the IPv4 addresses to PRL */
		if (add_router_name_to_internal_prl(r->name, rs_interval) < 0)
			return -1;
		r = r->next;
	}
	/* Error, if PRL is empty */
	if (!get_first_internal_pdr())
		return -1; 
	return 0;
}

/**
 * Gets source IPv4 Address of tunnel, either:
 * - IPv4 address of linked interface
 * - Detected outgoing IPv4 address
 * 0 if error
 **/
static uint32_t get_tunnel_saddr(const char* iface)
{
	uint32_t saddr;
	struct PRLENTRY* pr;

	if (iface) {
		saddr = get_if_addr(iface);
		if (saddr == 0) {
			if (verbose >= -1)
				syslog(LOG_ERR, "get_if_addr: %s\n", strerror(errno));
		}
		return saddr;
	}

	pr = get_first_internal_pdr();
	saddr = 0;

	while (pr) {
		struct sockaddr_in addr, addr2;
		socklen_t addrlen;
		int fd = socket (AF_INET, SOCK_DGRAM, 0);	
		if (fd < 0) {
			syslog(LOG_ERR, "socket: %s\n", strerror(errno));
			break;
		}

		/* Try a UDP connect (no packages are sent) */
		addr.sin_family = AF_INET;
		addr.sin_port = 0;
		addr.sin_addr.s_addr = pr->ip;
		if (connect (fd, (struct sockaddr*)&addr, sizeof(struct sockaddr_in))== 0) {
			/* Get local address of connected socket */
			addrlen = sizeof(addr2);
			getsockname(fd, (struct sockaddr *)&addr2, &addrlen);
			if (addrlen == sizeof(addr2)) {
				if (saddr == 0)
					saddr = addr2.sin_addr.s_addr;
				else if (saddr != addr2.sin_addr.s_addr) {
					syslog(LOG_WARNING,
						"Outgoing interface for PDR %s differs from %s. Removing from internal PRL.\n",
						inet_ntoa(addr.sin_addr), inet_ntoa(addr2.sin_addr));
					pr = del_internal_pdr(pr);
					close(fd);
					continue;
				}
			}
		} else  {
			syslog(LOG_WARNING, "PDR %s unreachable. Probing again next time.\n",
						inet_ntoa(addr.sin_addr));
		}
		close (fd);
	
		pr = pr->next;
	}
	return saddr;
}

/**
 * Wait until get_tunnel_saddr() successfully returns a source address
 **/
static uint32_t wait_for_link()
{
	uint32_t saddr;
	saddr = get_tunnel_saddr(interface_name);
	if (saddr == 0) {
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
			if (sleep(WAIT_FOR_LINK) || go_down)
				return 0; /* Interrupted by signal */
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


/**
 * Creates isatap tunnel interface for saddr
 * Brings tunnel UP
 **/
static void create_isatap_tunnel(uint32_t saddr)
{
	/* Create tunnel */
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

	/* Set MTU */
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
}

/**
 * Sets tunnel interface DOWN and delete it
 **/
static void delete_isatap_tunnel()
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

	pf = open(pid_file, O_WRONLY | O_CREAT, 0644);
	if (pf < 0) {
		syslog(LOG_ERR, "Cannot create pid file, terminating: %s\n", strerror(errno));
		exit(1);
	}

	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 0;

	if (fcntl(pf, F_SETLK, &fl) < 0) {
		syslog(LOG_ERR, "Cannot lock pid file, terminating: %s\n", strerror(errno));
		exit(1);
	}

	if (ftruncate(pf, 0) < 0) {
		syslog(LOG_ERR, "Cannot truncate pid file, terminating: %s\n", strerror(errno));
		exit(1);
	}

	snprintf(s, sizeof(s), "%d\n", (int)getpid());
	if (write(pf, s, strlen(s)) < strlen(s))
		syslog(LOG_ERR, "write: %s\n", strerror(errno));
	if (fsync(pf) < 0)
		syslog(LOG_ERR, "fsync: %s\n", strerror(errno));
}



/**
 * SIGINT, SIGTERM
 * 
 * kill child and go down
 **/
static void sigint_handler(int sig)
{
	signal(sig, SIG_DFL);
	if (verbose >= 0)
		syslog(LOG_NOTICE, "signal %d received, going down.\n", sig);
	if (child)
		kill(child, SIGHUP);
	go_down = 1;
}


/**
 * SIGHUP
 *
 * kill child to continue in main loop
 **/
static void sighup_handler(int sig)
{
	if (verbose >= 0)
		syslog(LOG_NOTICE, "SIGHUP received.\n");
	if (child)
		kill(child, SIGHUP);
}

static void setup_signals()
{
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);
	signal(SIGHUP, sighup_handler);
}



int main(int argc, char **argv)
{
	uint32_t saddr;

	openlog(NULL, LOG_PID | LOG_PERROR, syslog_facility);
	parse_options(argc, argv);

	if (daemonize == 1) {
		pid_t pid;

		pid = fork();
		if (pid < 0) {
			syslog(LOG_ERR, "fork: %s\n", strerror(errno));
			exit(1);
		}
		if (pid > 0) {
			/* Father */
			if (verbose >= 1)
				syslog(LOG_INFO, "Running isatap daemon as pid %d\n", (int)pid);
			exit(0);
		}
		/* Child */
		setsid();
		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		close(STDERR_FILENO);

	}
	
	if (pid_file != NULL)
		write_pid_file();

	setup_signals();
begin:
	/* Fill internal PRL and make sure we have at least one entry */
	while (fill_internal_prl() < 0) {
		if (verbose >= 0)
			syslog(LOG_INFO, "Internal PRL empty! Rechecking in %d sec.\n", WAIT_FOR_PRL);
		sleep(WAIT_FOR_PRL);
		if (go_down)
			goto end;
	}

	/* Wait till we find an outgoing interface for the first entry in the PRL */
	saddr = wait_for_link();
	if (go_down)
		goto end;
	if (saddr == 0)
		goto begin;
	create_isatap_tunnel(saddr);

	while (!go_down)
	{
		uint32_t saddr_n;
		int status;

		child = fork();
		if (child < 0) {
			syslog(LOG_ERR, "fork: %s\n",strerror(errno));
			break;
		}
		if (child) {
			/* Parent BEGIN */
			
			/* Wait for child to terminate */
			waitpid(child, &status, 0);
			if (WIFEXITED(status))
				status = WEXITSTATUS(status);
			if (verbose >= 2)
				syslog(LOG_INFO, "Solicitation Loop exited with status %d\n", status);
			child = 0;
			/* Parent END*/
		} else {
			/* Child BEGIN */
			status = run_solicitation_loop(tunnel_name, dns_interval * 1000, unpriv_username);
			closelog();
			exit(status);
			/* Child END */
		}
		/* Parent */
		if (go_down)
			break;

		if (status == EXIT_CHECK_PRL) {
			/* Child requested to recheck PRL, without taking the tunnel down */
			if (verbose >= 1)
				syslog(LOG_INFO, "Rechecking DNS entries for PRL\n");
			
			fill_internal_prl();
			prune_kernel_prl(tunnel_name);
			
			if (get_first_internal_pdr() == NULL) {
				/* If PRL suddenly is empty, restart from the beginning */
				delete_isatap_tunnel();
				goto begin;
			}
		}
		if (status == EXIT_ERROR_FATAL) {
			syslog(LOG_ERR, "Child exited with ERROR_FATAL. Going down.\n");
			break;
		}

		/* Try to detect link change */
		saddr_n = get_tunnel_saddr(interface_name);

		if (saddr_n != saddr || saddr_n == 0 || status == EXIT_ERROR_LAYER2) {
			syslog(LOG_WARNING, "Link change detected. Re-creating tunnel.\n");
			delete_isatap_tunnel();
			goto begin;
		}
	}
	delete_isatap_tunnel();

end:

 	if (pid_file) {
		if (unlink(pid_file) < 0)
			syslog(LOG_WARNING, "cannot unlink pid file: %s\n", strerror(errno));
	}
	closelog();

	return 0;
}
