#ifndef _NDISC_H_INCLUDED_
#define _NDISC_H_INCLUDED_


int create_rs_socket();
int send_rdisc(int fd, const char *dev, struct in6_addr *addr);



#endif
