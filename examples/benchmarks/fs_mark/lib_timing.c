/*
 * a timing utilities library
 *
 * Requires 64bit integers to work.
 *
 * %W% %@%
 *
 * Copyright (c) 2000 Carl Staelin.
 * Copyright (c) 1994-1998 Larry McVoy.
 * Distributed under the FSF GPL with
 * additional restriction that results may published only if
 * (1) the benchmark is unmodified, and
 * (2) the version in the sccsid below is included in the report.
 * Support for this development by Sun Microsystems is gratefully acknowledged.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>

#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
// #include <linux/types.h> Z

#define	nz(x)	((x) == 0 ? 1 : (x))

/*
 * I know you think these should be 2^10 and 2^20, but people are quoting
 * disk sizes in powers of 10, and bandwidths are all power of ten.
 * Deal with it.
 */
#define	MB	(1000*1000.0)
#define	KB	(1000.0)

/* typedef unsigned long long uint64; */

static struct timeval 	start_tv, stop_tv;


/*
 * Return the current time in microseconds since the epoch
 */
unsigned long long tvnow(void)
{
	unsigned long long usec_time;
	struct timeval now;

	(void) gettimeofday(&now, (struct timezone *) 0);

	/*
	 * Compute the time in usecs
	 */
	usec_time = now.tv_sec;
	usec_time *= 1000000;
	usec_time += now.tv_usec;

	return (usec_time);
}


/*
 * Start timing now.
 */
void
start(struct timeval *tv)
{
	if (tv == NULL) {
		tv = &start_tv;
	}
	(void) gettimeofday(tv, (struct timezone *) 0);
}

void
tvsub(struct timeval * tdiff, struct timeval * t1, struct timeval * t0)
{
	tdiff->tv_sec = t1->tv_sec - t0->tv_sec;
	tdiff->tv_usec = t1->tv_usec - t0->tv_usec;
	if (tdiff->tv_usec < 0 && tdiff->tv_sec > 0) {
		tdiff->tv_sec--;
		tdiff->tv_usec += 1000000;
		if (tdiff->tv_usec < 0) {
		  fprintf(stderr, "lat_fs: tvsub shows test time ran backwards!\n");
		  exit(1);
		}
	}

	/* time shouldn't go backwards!!! */
	if (tdiff->tv_usec < 0 || t1->tv_sec < t0->tv_sec) {
		tdiff->tv_sec = 0;
		tdiff->tv_usec = 0;
	}
}

unsigned long long
tvdelta(struct timeval *start, struct timeval *stop)
{
	struct timeval td;
	unsigned long long	usecs;

	tvsub(&td, stop, start);
	usecs = td.tv_sec;
	usecs *= 1000000;
	usecs += td.tv_usec;
	return (usecs);
}

/*
 * Stop timing and return real time in microseconds.
 */
unsigned long long
stop(struct timeval *begin, struct timeval *end)
{
	if (end == NULL) {
		end = &stop_tv;
	}
	(void) gettimeofday(end, (struct timezone *) 0);

	if (begin == NULL) {
		begin = &start_tv;
	}
	return (tvdelta(begin, end));
}





