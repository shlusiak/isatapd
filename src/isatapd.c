#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <netinet/in.h>


#define _GNU_SOURCE
#include <getopt.h>

#ifdef HAVE_CONFIG_H
	#include "config.h"
#endif

#include "tunnel.h"


static char* tunnel_name = NULL;
static char* interface_name = NULL;
static char* router_name = "isatap";
static int probe_interval = 10;
static int verbose = 0;



void show_help()
{
	fprintf(stderr, "Usage: isatapd [OPTIONS] interface...\n");
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
		case 'r': if (optarg)
				router_name = strdup(optarg);
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


void add_prl()
{
	printf("Adding routers: \n");
}


int main(int argc, char **argv)
{
	uint32_t saddr;
	parse_options(argc, argv);

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

	if (verbose>1)
		printf("%s created (%s, 0x%08X)\n", tunnel_name, interface_name, ntohl(saddr));
	tunnel_add(interface_name, tunnel_name, saddr);

	if (verbose)
		printf("%s -> up\n", tunnel_name);
	tunnel_up(tunnel_name);


	add_prl();
	sleep(5);


	if (verbose)
		printf("%s -> down\n", tunnel_name);
	tunnel_down(tunnel_name);
	
	if (verbose>1)
		printf("%s deleted\n", tunnel_name);
	tunnel_del(tunnel_name);

	return 0;
}
