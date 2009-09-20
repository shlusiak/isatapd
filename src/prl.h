#ifndef _PRL_H_INCLUDED_
#define _PRL_H_INCLUDED_


struct PRLENTRY {
	struct PRLENTRY* next;
	uint32_t ip;
	int interval;
};


void flushPRL();
void addPR(struct PRLENTRY* pr);
struct PRLENTRY* newPR();
struct PRLENTRY* delPR(struct PRLENTRY* pr);
struct PRLENTRY* findPR(uint32_t ip);
struct PRLENTRY* getFirstPR();

#endif
