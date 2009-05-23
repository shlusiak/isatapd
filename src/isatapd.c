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
static int   probe_interval = 10;
static int   verbose = 0;
static int volatile go_down = 0;


void show_help()
{
	fprintf(stderr, "Usage: isatapd [OPTIONS] interface...\n");
	fprintf(stderr, "       -h --help       display this message\n");
	fprintf(stderr, "       -n --name       name of the tunnel\n");
	fprintf(stderr, "                       default: auto\n");
	fprintf(stderr, "       -r --router     a potential router (up to 10).\n");
	fprintf(stderr, "                       default: 'isatap'.\n");
	fprintf(stderr, "       -t --interval   [to be implemented]\n");
	fprintf(stderr, "       -v --verbose    increases verbosity\n");
	fprintf(stderr, "       interface       the link device\n");

	exit(0);
}

void parse_options(int argc, char** argv)
{
	int c;
	const char* short_options = "hn:t:r:v";
	struct option long_options[] = {
		{"help", 0, NULL, 'h'},
		{"name", 1, NULL, 'n'},
		{"router", 1, NULL, 'r'},
		{"interval", 1, NULL, 't'},
		{"verbose", 0, NULL, 'v'},
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
		case 't': if (optarg) {
				probe_interval = atoi(optarg);
				if (probe_interval <= 0) {
					fprintf(stderr, "%s: invalid cardinal -- %s\n", argv[0], optarg);
					show_help();
				}
			}
			break;
		case 'v': verbose++;
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
		fprintf(stderr, "%s: option required -- interface\n", argv[0]);
		show_help();
	}
}


int add_prl(const char* host)
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
		fprintf(stderr, "getaddrinfo(\"%s\"): %s\n", host, gai_strerror(err));
		return -1;
	}

	p=addr_info;
	while (p)
	{
		struct in_addr addr;
		struct in6_addr addr6;
		addr = ((struct sockaddr_in*)(p->ai_addr))->sin_addr;
		if (verbose)
			printf("Adding PDR %s\n", inet_ntoa(addr));
		tunnel_add_prl(tunnel_name, addr.s_addr, 1);
		
		addr6.s6_addr32[0] = htonl(0xfe800000);
		addr6.s6_addr32[1] = htonl(0x00000000);
		addr6.s6_addr32[2] = htonl(0x00005efe);
		addr6.s6_addr32[3] = addr.s_addr;

		send_rdisc(tunnel_name, &addr6);

		addr6.s6_addr32[0] = htonl(0xfe800000);
		addr6.s6_addr32[1] = htonl(0x00000000);
		addr6.s6_addr32[2] = htonl(0x02005efe);
		addr6.s6_addr32[3] = addr.s_addr;

		send_rdisc(tunnel_name, &addr6);


		p=p->ai_next;
	}	
	freeaddrinfo(addr_info);

	
	return 0;
}

void handler(int sig)
{
	printf("SIGINT received, going down.\n");
	signal(SIGINT, SIG_DFL);
	go_down = 1;
}

void alarmhandler(int sig)
{
	printf("Alarm\n");
	alarm(10);
}

int main(int argc, char **argv)
{
	uint32_t saddr;
	int i;

	parse_options(argc, argv);

	signal(SIGINT, handler);

	if (tunnel_name == NULL)
	{
		tunnel_name = (char *)malloc(strlen(interface_name)+3+1);
		strcpy(tunnel_name, "is_");
		strcat(tunnel_name, interface_name);
	}

	saddr = get_if_addr(interface_name);
	if (saddr == 0) {
		fprintf(stderr, "%s: interface %s does not have a valid IPv4 address\n", argv[0], interface_name);
		exit(1);
	}

	
	if (tunnel_add(tunnel_name, interface_name, saddr) < 0) {
		fprintf(stderr, "%s: error creating tunnel interface %s\n", argv[0], tunnel_name);
		exit(1);
	}

	if (verbose>1)
		printf("%s created (%s, 0x%08X)\n", tunnel_name, interface_name, ntohl(saddr));

	tunnel_up(tunnel_name);
	if (verbose)
		printf("%s -> up\n", tunnel_name);

	for (i = 0; i < sizeof(router_name)/sizeof(router_name[0]); i++)
		if (router_name[i])
			add_prl(router_name[i]);

	printf("Ctrl+C to abort...\n");

	signal(SIGALRM, alarmhandler);
	
	alarm(10);

	while (!go_down)
		pause();

	tunnel_down(tunnel_name);
	if (verbose)
		printf("%s -> down\n", tunnel_name);
	
	tunnel_del(tunnel_name);
	if (verbose>1)
		printf("%s deleted\n", tunnel_name);

	return 0;
}
