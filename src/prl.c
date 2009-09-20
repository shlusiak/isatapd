#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <errno.h>

#include <netinet/in.h>

#ifdef HAVE_CONFIG_H
	#include "config.h"
#endif


#include "prl.h"




static struct PRLENTRY* prl_head = NULL;

void flushPRL() {
	while (prl_head)
		delPR(prl_head);
}

void addPR(struct PRLENTRY* pr) {
	pr->next = prl_head;
	prl_head = pr;
}

struct PRLENTRY* newPR() {
	struct PRLENTRY* n;
	n = (struct PRLENTRY*)malloc(sizeof(struct PRLENTRY));

	n->ip = 0;
	n->next = NULL;
	n->interval = 0;

	return n;
}

struct PRLENTRY* delPR(struct PRLENTRY* pr) {
	struct PRLENTRY* prev = prl_head;
	if (pr == prl_head) {
		prl_head = pr->next;
		free(pr);
		return prl_head;
	}
	while (prev) {
		if (prev->next == pr) {
			prev->next = pr->next;
			free(pr);
			return prev->next;
		}
		prev = prev->next;
	}
	return NULL;
}

struct PRLENTRY* findPR(uint32_t ip) {
	struct PRLENTRY* cur = prl_head;
	while (cur) {
		if (cur->ip == ip)
			return cur;
		cur = cur->next;
	}
	return NULL;
}

struct PRLENTRY* getFirstPR() {
	return prl_head;
}

