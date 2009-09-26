#ifndef _ISATAP_H_INCLUDED_
#define _ISATAP_H_INCLUDED_


#define   MAX_RTR_SOLICITATION_DELAY          1 /*secs*/
#define   RTR_SOLICITATION_INTERVAL           4 /*secs*/
#define   MAX_RTR_SOLICITATIONS               3 /*transmissions*/
#define   DEFAULT_MINROUTERSOLICITINTERVAL  120 /*secs*/


#define EXIT_ERROR_LAYER2 (100)
#define EXIT_CHECK_PRL (101)
#define EXIT_ERROR_FATAL (102)


int add_router_name_to_prl(const char* host, int interval);
int run_solicitation_loop(char* tunnel_name, int check_prl_timeout);


#endif
