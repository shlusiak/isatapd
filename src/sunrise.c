/*
 * sunrise.c    Detect presence of another IPv6 default route
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
#include <syslog.h>
#include <errno.h>

#include <net/route.h>

#include "main.h"
#include "sunrise.h"



#define _PATH_PROCNET_ROUTE6            "/proc/net/ipv6_route"


int sunrise_get(char* exclude_interface) {
	FILE *fp;
	char buff[4096], iface[16];
	char addr6p[33], saddr6p[33], naddr6p[33];
	int num, iflags, metric, refcnt, use, prefix_len, slen;

	fp = fopen(_PATH_PROCNET_ROUTE6, "r");
	if (!fp) {
		syslog(LOG_WARNING, "Sunset failed, continuing. Opening %s: %s\n",
		       _PATH_PROCNET_ROUTE6, strerror(errno));
		return 0;
	}

	while (fgets(buff, 1023, fp)) {
		num = sscanf(buff, "%32s %02x %32s %02x %32s %08x %08x %08x %08x %s\n",
			addr6p, 
			&prefix_len,
			saddr6p,
			&slen,
			naddr6p,
			&metric, &refcnt, &use, &iflags, iface);

		addr6p[32] = '\0';
		saddr6p[32] = '\0';
		naddr6p[32] = '\0'; 

		if (iflags & RTF_REJECT)
			continue;
		if (strcmp(iface, exclude_interface) == 0)
			continue;
		if ((prefix_len == 0) && (strcmp(addr6p, "00000000000000000000000000000000") == 0)) {
			if (verbose >= 1)
				syslog(LOG_INFO, "Existing IPv6 default route found, dev %s\n", iface);
			fclose(fp);
			return 1;
		}
	}

	fclose(fp);
	return 0;
}

