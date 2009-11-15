#ifndef _NDISC_H_INCLUDED_
#define _NDISC_H_INCLUDED_

/* Create a socket for sending RS */
int create_rs_socket();

/* Send a RS */
int send_rdisc(int fd, int ifindex, struct in6_addr *addr);

/* Reveice and parse a RA */
int recvadv(int fd, int ifindex);


#endif
