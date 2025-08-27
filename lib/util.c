/*
 * This file is part of Libipcon
 * Copyright (C) 2017-2025 Seimizu Joukan
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU Lesser General Public License for more details.
 */


#include <stdlib.h>
#include "util.h"

void le_init(struct link_entry *le)
{
	if (le) {
		le->head = NULL;
		le->prev = le->next = le;
	}
}

void lh_init(struct link_entry_head *lh)
{
	if (lh) {
		struct link_entry *le = LINK_ENTRY(lh);

		le->prev = le->next = le->head = LINK_ENTRY(lh);
		lh->cnt = 0;
	}
}

void le_addtail(struct link_entry_head *head, struct link_entry *new)
{
	struct link_entry *h = (struct link_entry *)head;
	struct link_entry *hp = NULL;

	if (!h || !new)
		return;

	hp = h->prev;

	if (hp == h) {
		h->prev = new;
		new->next = h;
		h->next = new;
		new->prev = h;
	} else {
		h->prev = new;
		new->next = h;

		hp->next = new;
		new->prev = hp;
	}

	new->head = h;
	head->cnt++;
}

void *le_next(struct link_entry *le)
{
	if (!le || le->next == le->head)
		return NULL;

	return (void *)le->next;
}

void *le_remove(struct link_entry *le)
{
	if (!le || !le->head || !le->next || !le->prev)
		return (void *)le;

	le->next->prev = le->prev;
	le->prev->next = le->next;
	LINK_ENTRY_HEAD(le->head)->cnt--;

	le->head = NULL;
	le->prev = le->next = le;
}

struct link_entry_head *le_gethead(struct link_entry *le)
{
	if (le)
		return LINK_ENTRY_HEAD(le->head);

	return NULL;
}
__u32 le_getcnt(struct link_entry_head *le)
{
	if (le)
		return le->cnt;

	return 0;
}
