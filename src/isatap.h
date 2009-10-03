#ifndef _ISATAP_H_INCLUDED_
#define _ISATAP_H_INCLUDED_


#define   DEFAULT_ROUTER_NAME                 "isatap"
#define   MAX_RTR_SOLICITATION_DELAY          1 /*secs*/
#define   RTR_SOLICITATION_INTERVAL           4 /*secs*/
#define   MAX_RTR_SOLICITATIONS               3 /*transmissions*/
#define   DEFAULT_MINROUTERSOLICITINTERVAL  120 /*secs*/
#define   WAIT_FOR_LINK                      10 /* seconds between polling, if link is down */


#define EXIT_ERROR_LAYER2 (100)
#define EXIT_CHECK_PRL (101)
#define EXIT_ERROR_FATAL (102)


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

int add_router_name_to_internal_prl(const char* host, int interval);
int prune_kernel_prl(const char* dev);
int run_solicitation_loop(char* tunnel_name, int check_prl_timeout);


#endif
