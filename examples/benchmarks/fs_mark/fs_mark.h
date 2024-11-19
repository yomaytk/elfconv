/* 
 * Copyright (C) 2003-2004 EMC Corporation
 *
 * Written by Ric Wheeler <ric@emc.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */


/*
 * Default and maximum parameters.
 */
#define MAX_IO_BUFFER_SIZE 	(1024 * 1024) 	/* Max write buffer size is 1MB */
#define MAX_FILES		(1000000)	/* Max number of files to test of each size */
#define MAX_THREADS		(64)		/* Max number of threads allowed */
#define MAX_NAME_PATH		(1000)		/* Length of the pathname before the leaf */
#define FILENAME_SIZE		(128) 		/* Max length of filenames */
#define MAX_STRING_SIZE		(160)	    	/* Max number of bytes in a string */

/*
 * Default values
 */
#define DEFAULT_SECS_PER_DIR	(180)
#define DEFAULT_FILE_SIZE	(50 * 1024)
#define DEFAULT_IO_SIZE		(16 * 1024)
#define DEFAULT_NUM_FILES	(1000)
#define DEFAULT_NAME_LEN	(40)
#define DEFAULT_RAND_NAME	(24)
#define DEFAULT_SUBDIR_CNT	(0)


/*
 * Subdirectory policy types
 */
#define DIR_NO_SUBDIRS		(0)	    /* No policy: Use only one directory for all files */
#define DIR_ROUND_ROBIN		(1)	    /* Round robin during write phase */
#define DIR_TIME_HASH		(2)	    /* Hash into subdirectories based on time stamp */
#define NUM_DIR_POLICIES	(3)

const char dir_policy_string[NUM_DIR_POLICIES][MAX_STRING_SIZE] = {
	"No subdirectories", 
	"Round Robin between directories", 
	"Time based hash between directories"
};

/*
 * Dir policy set to non by default
 */
int	dir_policy = DIR_NO_SUBDIRS;

/*
 * Bits to control the various sync routines (fsync and system level sync). 
 */

#define FSYNC_NONE		(0)
#define FSYNC_BEFORE_CLOSE	(0x1)
#define	FSYNC_SYNC_SYSCALL	(0x2)
#define FSYNC_FIRST_FILE	(0x4)
#define FSYNC_POST_REVERSE	(0x8)
#define FSYNC_POST_IN_ORDER	(0x10)


#define SYNC_TEST_NONE		(0)	    					/* -S 0 */
#define SYNC_TEST_PER_FILE	(FSYNC_BEFORE_CLOSE)				/* Default: -S 1 */
#define SYNC_TEST_PER_THREAD	(FSYNC_SYNC_SYSCALL | FSYNC_FIRST_FILE)		/* -S 2 */
#define SYNC_TEST_REVERSE	(FSYNC_POST_REVERSE)				/* -S 3 */
#define SYNC_TEST_REVERSE_SYNC	(FSYNC_POST_REVERSE | FSYNC_SYNC_SYSCALL)	/* -S 4 */
#define SYNC_TEST_POST		(FSYNC_POST_IN_ORDER)				/* -S 5 */
#define SYNC_TEST_POST_SYNC	(FSYNC_POST_IN_ORDER | FSYNC_SYNC_SYSCALL)	/* -S 6 */
#define NUM_SYNC_METHODS		(7)

const char sync_policy_string[NUM_SYNC_METHODS][MAX_STRING_SIZE] = {
	"NO SYNC: Test does not issue sync() or fsync() calls.",
	"INBAND FSYNC: fsync() per file in write loop.",
	"SYSTEM SYNC/SINGLE FSYNC: Issue sync() after main write loop and 1 file fsync() per subdirectory.",
	"POST REVERSE: Reopen and fsync() each file in reverse order after main write loop.",
	"SYNC POST REVERSE: Issue sync() and then reopen and fsync() each file in reverse order after main write loop.",
	"POST: Reopen and fsync() each file in order after main write loop.",
	"SYNC POST: Issue sync() and then reopen and fsync() each file in order after main write loop."
};


/*
 * Use the normal fsync() per file by default
 */
int sync_method = SYNC_TEST_PER_FILE;
int sync_method_type = 1;

/*
 * File and IO control variables
 */
int 	io_buffer_size = DEFAULT_IO_SIZE; 	/* IO buffer size  */
unsigned int	file_size = DEFAULT_FILE_SIZE;	/* File size to create during run  */
int	num_files = DEFAULT_NUM_FILES;		/* Number of times to test each file size */
int	name_len = DEFAULT_NAME_LEN;		/* Number of characters in a filename */
int	rand_len = DEFAULT_RAND_NAME;		/* Number of random characters in a filename */

/*
 * Variables to control how many subdirectories & how to fill them
 */
int	num_subdirs = DEFAULT_SUBDIR_CNT;	/* Number of subdirectories to use */
int	num_per_subdir = 0;			/* Determine how many files to write to each subdirectory */
int	num_dirs = 0;				/* Number of directories passed in as args */
int 	files_in_subdir = 0;
int 	current_subdir = 0;
unsigned long secs_per_directory = DEFAULT_SECS_PER_DIR;


/*
 * Misc booleans & globals
 */
int	keep_files = 0;				/* Should the test clean up after itself */
int	num_threads = 1;			/* Number of threads */
int	do_fill_fs = 0;				/* Run until the file system is full  */
int	verbose_stats = 0;		    	/* Print complete stats for each system call */
char 	log_file_name[PATH_MAX] = "fs_log.txt"; /* Log file name for run */
FILE	*log_file_fp;				/* Parent file pointer for log file  */
FILE	*child_log_file_fp;			/* Child file pointer for log file  */

unsigned int loop_count = 0;			/* How many times to loop */
unsigned int file_count = 0;			/* How many files written in this run  */
unsigned long long start_sec_time = 0;

static char io_buffer[MAX_IO_BUFFER_SIZE];	/* Buffer used in writes to files */

struct name_entry {
    char f_name[FILENAME_SIZE];			/* Actual name of file in directory without path */
    char write_dir[MAX_NAME_PATH]; 		/* Name of directory file is written to */
    char target_dir[MAX_NAME_PATH];	 	/* Name of directory when & if file is renamed */
};

struct name_entry *names = NULL; 		/* Array of names & paths used in test  */

static char rand_name[FILENAME_SIZE];
static char seq_name[FILENAME_SIZE];

typedef struct {
	pid_t	child_pid;
	char 	test_dir[PATH_MAX]; 		/* Directory name to use to create test files in */
} child_job_t;

/*
 * Structure used to record statisitics on each run of files.
 */
typedef struct {
	unsigned int file_count;	    	/* Number of files in run */
	float files_per_sec;			/* Effective (wallclock time based) number of files written/second */
    	unsigned long long app_overhead_usec; 	/* Time spent by application not in "file writing" related system calls */
    
	/*
	 * Times for creat() system call in usecs
	 */
	unsigned long long min_creat_usec;
	unsigned long long avg_creat_usec;
	unsigned long long max_creat_usec;

	/*
	 * Times for write() system call in usecs
	 */
	unsigned long long min_write_usec;
	unsigned long long avg_write_usec;
	unsigned long long max_write_usec;

	/*
	 * Times for fsync() system call in usecs
	 */
	unsigned long long min_fsync_usec;
	unsigned long long avg_fsync_usec;
	unsigned long long max_fsync_usec;

	/*
	 * Times in sync() system call
	 */
	unsigned long long min_sync_usec;
	unsigned long long avg_sync_usec;
	unsigned long long max_sync_usec;
	
	/*
	 * Times for unlink() system call in usecs
	 */
	unsigned long long min_unlink_usec;
	unsigned long long avg_unlink_usec;
	unsigned long long max_unlink_usec;

	/*
	 * Times for close() system call in usecs
	 */
	unsigned long long min_close_usec;
	unsigned long long avg_close_usec;
	unsigned long long max_close_usec;
} fs_mark_stat_t;


/*
 * For each child, we need to track its pid and the directory that it is to run in
 */
child_job_t child_tasks[MAX_THREADS];

/*
 * lib_timing.c prototypes
 */
void start(struct timeval *);
unsigned long long stop(struct timeval *, struct timeval *);
unsigned long long tvnow(void);
