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


#ifndef __TIMESTAMP_MSG_H__
#define __TIMESTAMP_MSG_H__

#include <sys/time.h>

#define MAX_STAMP_CNT	5
#define MARKER_MAX_LEN	4
#define TSLOG_BUF_SIZE	(32 * MAX_STAMP_CNT)

struct ts_msg {
	int last_free_idx;
	struct timeval ts[MAX_STAMP_CNT];
	char mark[MAX_STAMP_CNT][MARKER_MAX_LEN];
};

static inline void tsm_init(struct ts_msg *tm)
{
	if (tm)
		memset(tm, 0, sizeof(*tm));
}

static inline struct ts_msg *tsm_alloc(void)
{
	struct ts_msg *tm = NULL;

	tm = malloc(sizeof(*tm));
	tsm_init(tm);

	return tm;
}

static inline void tsm_recod(char *marker, struct ts_msg *tm)
{
	if (tm && tm->last_free_idx < MAX_STAMP_CNT) {
		int i = tm->last_free_idx;

		gettimeofday(&tm->ts[i], NULL);
		if (marker) {
			strncpy(tm->mark[i],
				marker,
				MARKER_MAX_LEN);
			tm->mark[i][MARKER_MAX_LEN - 1] = '\0';
		} else {
			sprintf(tm->mark[i], "m%d", i);
		}

		tm->last_free_idx++;
	}
}

static inline void get_tv_diff(struct timeval *snd_ts,
		struct timeval *rcv_ts, struct timeval *diff)
{

	if (!snd_ts || !rcv_ts || !diff)
		return;

	if (rcv_ts->tv_usec > snd_ts->tv_usec) {
		diff->tv_sec = rcv_ts->tv_sec - snd_ts->tv_sec;
		diff->tv_usec = rcv_ts->tv_usec - snd_ts->tv_usec;
	} else {
		diff->tv_sec = rcv_ts->tv_sec - snd_ts->tv_sec - 1;
		diff->tv_usec = 1000000 - snd_ts->tv_usec + rcv_ts->tv_usec;
	}
}


static inline void tsm_delta(struct ts_msg *tm, char *buf, int size)
{
	int i;
	struct timeval diff;
	char *p = buf;
	int len = 0;

	if (!tm || !buf)
		return;

	if (tm->last_free_idx < 1)
		return;

	if (size < TSLOG_BUF_SIZE)
		return;


	get_tv_diff(&tm->ts[0], &tm->ts[tm->last_free_idx - 1], &diff);
	len = sprintf(p, "%s->%s: %d.%06d ",
			tm->mark[0],
			tm->mark[tm->last_free_idx - 1],
			(int)diff.tv_sec,
			(int)diff.tv_usec);

	p += len;

	for (i = 0; i < tm->last_free_idx - 1; i++) {
		get_tv_diff(&tm->ts[i], &tm->ts[i + 1], &diff);
		len = sprintf(p, "%s->%s: %d.%06d ",
			tm->mark[i],
			tm->mark[i + 1],
			(int)diff.tv_sec,
			(int)diff.tv_usec);
		p += len;
	}
	*p = '\0';
}

#endif
