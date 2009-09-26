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


void flush_internal_prl();
void add_internal_pdr(struct PRLENTRY* pr);
struct PRLENTRY* new_internal_pdr();
struct PRLENTRY* del_internal_pdr(struct PRLENTRY* pr);
struct PRLENTRY* find_internal_pdr_by_addr(uint32_t ip);
struct PRLENTRY* find_internal_pdr_by_addr6(struct in6_addr *addr);
struct PRLENTRY* get_first_internal_pdr();

#endif
