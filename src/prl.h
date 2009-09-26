#ifndef _PRL_H_INCLUDED_
#define _PRL_H_INCLUDED_


struct PRLENTRY {
	struct PRLENTRY* next;
	uint32_t ip;
	struct sockaddr_in6 addr6;
	int interval;
	int next_timeout;
	int rs_sent;
};


void flushPRL();
void addPR(struct PRLENTRY* pr);
struct PRLENTRY* newPR();
struct PRLENTRY* delPR(struct PRLENTRY* pr);
struct PRLENTRY* findPR(uint32_t ip);
struct PRLENTRY* findPR_by_addr6(struct in6_addr *addr);
struct PRLENTRY* getFirstPR();

#endif
