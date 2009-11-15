#ifndef _ISATAP_H_INCLUDED_
#define _ISATAP_H_INCLUDED_


/* Defaults */
#define   DEFAULT_UNPRIV_USERNAME             "nobody"
#define   DEFAULT_TUNNEL_NAME		      "is0"
#define   DEFAULT_TTL                         64
#define   DEFAULT_MTU                         0
#define   DEFAULT_ROUTER_NAME                 "isatap"
#define   MAX_RTR_SOLICITATION_DELAY          1 /*secs*/
#define   RTR_SOLICITATION_INTERVAL           4 /*secs*/
#define   MAX_RTR_SOLICITATIONS               3 /*transmissions*/
#define   DEFAULT_MINROUTERSOLICITINTERVAL  120 /*secs*/
#define   DEFAULT_PRLREFRESHINTERVAL       3600 /*secs*/
#define   WAIT_FOR_LINK                      60 /* seconds between polling, if link is down */
#define   WAIT_FOR_PRL                       60 /* seconds between polling, if PRL is empty */


/* Return values for run_solicitation_loop() */
#define EXIT_ERROR_LAYER2	100
#define EXIT_CHECK_PRL		101
#define EXIT_ERROR_FATAL	102


struct PRLENTRY {
	struct PRLENTRY* next;		/* next linked list element */

	struct PRLENTRY* sibling;	/* If there is another LL IPv6 address for same IPv4 address */
	uint32_t ip;			/* IPv4 address */
	struct sockaddr_in6 addr6;	/* Calculated LL IPv6 address */

	int default_timeout;		/* Default lifetime */
	int next_timeout;		/* Time in ms for next RS */
	int rs_sent;			/* Number of RS already sent */
	int stale;			/* Find stale PRL entries, that are not in DNS anymore */
};


void flush_internal_prl();
void add_internal_pdr(struct PRLENTRY* pr);
struct PRLENTRY* new_internal_pdr();
struct PRLENTRY* del_internal_pdr(struct PRLENTRY* pr);
struct PRLENTRY* find_internal_pdr_by_addr(uint32_t ip);
struct PRLENTRY* find_internal_pdr_by_addr6(struct in6_addr *addr);
struct PRLENTRY* get_first_internal_pdr();

int add_router_name_to_internal_prl(const char* host, int default_timeout);
int prune_kernel_prl(const char* dev);
int run_solicitation_loop(char* tunnel_name, int check_prl_timeout, char* username);


#endif

