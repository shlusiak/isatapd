#ifndef _ISATAP_H_INCLUDED_
#define _ISATAP_H_INCLUDED_


int add_router_name_to_prl(const char* host, int interval);
int run_solicitation_loop(char* tunnel_name);


#endif
