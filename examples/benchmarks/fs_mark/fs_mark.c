/* 
 * Copyright (C) 2003-2004 EMC Corporation
 *
 * fs_mark: Benchmark synchronous/async file creation
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

/* gratuitous change */
/*
 * Version string should be bumped on major revision changes
 */
char *fs_mark_version = "3.3";

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
// #include <sys/vfs.h>
#include <sys/statfs.h>
#include <sys/time.h>

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <float.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/statfs.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

// #include <linux/types.h>
// #include <linux/limits.h>
// #include <linux/unistd.h>

#define PATH_MAX 4096

#include "fs_mark.h"

static double second(void)

{
  return ((double) ((double) clock() / (double) CLOCKS_PER_SEC));
}

void cleanup_exit(void)
{
	char child_log_file_name[PATH_MAX];

	sprintf(child_log_file_name, "%s.%d", log_file_name, getpid());
	unlink(child_log_file_name);

	exit(1);
}

void usage(void)
{
	fprintf(stderr,
		"Usage: fs_mark\n%s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s",
		"\t-h <print usage and exit>\n",
		"\t-k <keep files after each iteration>\n",
		"\t-F <run until FS full>\n",
		"\t-S Sync Method (0:No Sync, 1:fsyncBeforeClose, "
		"2:sync/1_fsync, 3:PostReverseFsync, "
		"4:syncPostReverseFsync, 5:PostFsync, 6:syncPostFsync)\n",
		"\t[-D number (of subdirectories)]\n",
		"\t[-N number (of files in each subdirectory in Round Robin mode)]\n",
		"\t[-d dir1 ... -d dirN]\n", "\t[-l log_file_name]\n",
		"\t[-l log_file_name]\n",
		"\t[-L number (of iterations)]\n",
		"\t[-n number (of files per iteration)]\n",
		"\t[-p number (of total bytes file names)]\n",
		"\t[-r number (of random bytes in file names)]\n",
		"\t[-s byte_count (size in bytes of each file)]\n",
		"\t[-t number (of total threads)]\n",
		"\t[-w number (of bytes per write() syscall)]\n");
	cleanup_exit();
	return;
}

/*
 * Run through the specified arguments and make sure that they make sense.
 */
void process_args(int argc, char **argv, char **envp)
{
	int ret;

  // -d test/dir1
  if (mkdir("testdir1", 0777) == 0) {
    printf("testdir1 is created.\n");
  } else {
    printf("failed to make testdir1.\n");
  }
  strncpy(child_tasks[num_dirs].test_dir, "testdir1", PATH_MAX);
  // -s 
  file_size = 51200;
  // -n
  num_files = 1024;
  return;

	/*
	 * Parse all of the options that the user specified.
	 */
	while ((ret =
		getopt(argc, argv, "vhkFr:S:N:D:d:l:L:n:p:s:t:w:")) != EOF) {
		switch (ret) {
		case 'v':	/* verbose stats */
			verbose_stats = 1;
			break;

		case 'D':	/* Use Multiple directories */
			num_subdirs = atoi(optarg);
			if (num_subdirs < 2) {
				fprintf(stderr,
					"Number of subdirs needs to be greater than 1\n");
				usage();
			}
			/*
			 * Change the policy to a good multi-subdir one
			 */
			if (dir_policy == DIR_NO_SUBDIRS)
			    dir_policy = DIR_TIME_HASH;
			break;

		case 'd':	/* Set directory path */
			if (num_dirs > MAX_THREADS) {
				fprintf(stderr,
					"Max number of threads (and directories) is %d\n",
					MAX_THREADS);
				usage();
			}
			if (strlen(optarg) >= MAX_NAME_PATH) {
				fprintf(stderr,
					"fs_mark: %s directory pathname too long (must be less than %d bytes)\n",
					optarg, MAX_NAME_PATH);
				usage();
			}
			strncpy(child_tasks[num_dirs].test_dir, optarg,
				PATH_MAX);
			num_dirs++;
			break;

		case 'F':	/* Run until FS is full */
			keep_files = 1;	/* Set keep files as well (hard to fill fs without this!) */
			do_fill_fs = 1;
			break;

		case 'k':	/* Leave test files at end */
			keep_files = 1;
			break;

		case 'l':	/* Log file name */
			strncpy(log_file_name, optarg, PATH_MAX);
			break;

		case 'L':	/* number of iterations */
			loop_count = atoi(optarg);
			keep_files = 1;			/* Set keep files as well */
			break;

		case 'n':	/* Set number of files to test of each size */
			num_files = atoi(optarg);
			if (num_files > MAX_FILES) {
				fprintf(stderr, "Max files is %d\n", MAX_FILES);
				usage();
			}
			break;

		case 'N':	/* Set number of files to write into each subdirectory */
			dir_policy = DIR_ROUND_ROBIN;
			num_per_subdir = atoi(optarg);
			break;

		case 'p':	/* Set size of names in directories */
			name_len = atoi(optarg);
			if (name_len > FILENAME_SIZE) {
				fprintf(stderr, "Max filename size is %d\n",
					FILENAME_SIZE);
				usage();
			}
			break;

		case 's':	/* Set specific size to test */
			file_size = atoi(optarg);
			break;

		case 'r':	/* Use random file names */
			rand_len = atoi(optarg);
			break;

		case 'S':	/* Turn off sync and fsync */
			sync_method_type = atoi(optarg);
			switch (sync_method_type) {
			case 0:
				sync_method = 0;
				break;
			case 1:
				sync_method = SYNC_TEST_PER_FILE;
				break;
			case 2:
				sync_method = SYNC_TEST_PER_THREAD;
				break;
			case 3:
				sync_method = SYNC_TEST_REVERSE;
				break;
			case 4:
				sync_method = SYNC_TEST_REVERSE_SYNC;
				break;
			case 5:
				sync_method = SYNC_TEST_POST;
				break;
			case 6:
				sync_method = SYNC_TEST_POST_SYNC;
				break;

			default:
				fprintf(stderr, "Max filename size is %d\n",
					FILENAME_SIZE);
				usage();
			}
			break;

		case 't':	/* Set number of threads */
			num_threads = atoi(optarg);
			if (num_threads > MAX_THREADS) {
				fprintf(stderr, "Max threads is %d\n",
					MAX_THREADS);
				usage();
			}
			break;

		case 'w':	/* Set write buffer size */
			io_buffer_size = atoi(optarg);
			if (io_buffer_size > MAX_IO_BUFFER_SIZE) {
				fprintf(stderr, "MAX IO buffer size is %d\n",
					MAX_IO_BUFFER_SIZE);
				usage();
			}
			break;

		case 'h':	/* Print usage and exit */
			usage();
			break;

		default:
			usage();
		}
	}

	if (num_dirs == 0) {
		fprintf(stderr,
			"Must specify at least one directory with -d switch\n");
		usage();
	}
	if ((num_subdirs == 0) && (num_per_subdir > 0)) {
		fprintf(stderr,
			"Must specify at more than 1 subdirectory with -D switch"
			" for -N num_per_subdir to make sense\n");
		usage();
	}

	/*
	 * We need at least one thread per specified directory.
	 * Also, if we specify more threads than directories, divide 
	 * up the threads & make sure that an even number of threads runs 
	 * in each one.
	 */
	if (num_dirs > num_threads)
		num_threads = num_dirs;
	else {
		int threads_per_dir, i, j;

		threads_per_dir = num_threads / num_dirs;
		if (((num_dirs * threads_per_dir) != num_threads) ||
		    ((num_dirs * threads_per_dir) > MAX_THREADS)) {
			fprintf(stderr,
				"Threads (%d) must be an even multiple the number of directories"
				" (%d) and less than %d \n",
				num_threads, num_dirs, MAX_THREADS);
			usage();
		}
		for (i = 0; i < num_dirs; i++)
			for (j = 1; j < threads_per_dir; j++) {
				strncpy(child_tasks[i + (j * num_dirs)].
					test_dir, child_tasks[i].test_dir,
					PATH_MAX);
			}
	}
	return;
}

/*
 * Extract & return the file name from the child_tasks array
 */
char *find_dir_name(int pid)
{
	int num_dir;

	for (num_dir = 0; num_dir < MAX_THREADS; num_dir++) {
		if (child_tasks[num_dir].child_pid == pid)
			break;
	}

	return (child_tasks[num_dir].test_dir);
}

/*
 * Setup a file name.
 */
void setup_file_name(int file_index, pid_t my_pid)
{
	int seq_len;
	int j, pad, skip;
	unsigned long sec_time;
	char *my_dir;
	my_dir = find_dir_name(my_pid);
	char subdir_name[MAX_NAME_PATH];
	struct timeval now;

	/*
	 * Get the current time.
	 */
	(void) gettimeofday(&now, (struct timezone *) 0);
	sec_time = now.tv_sec;
	
	/*
	 * If this is the first run, record this time in
	 * start_sec_time.
	 */
	if (start_sec_time == 0) {
	    start_sec_time = sec_time;
	}

	/*
	 * Each filename will be name_len characters long.
	 * If random characters are requested, they go at the end of the filename.
	 * By default, all names are only sequential.
	 */
	seq_len = name_len - rand_len;

	if (names == NULL) {
		if ((names =
		     (struct name_entry *)calloc(sizeof(struct name_entry), num_files)) == NULL) {
			fprintf(stderr,
				"fs_mark: failed to allocate memory for file names: %s\n",
				strerror(errno));
			cleanup_exit();
		}
	}

	/*
	 * Now pick a directory to stick this file in.
	 * 
	 */
	switch (dir_policy) {
	case DIR_NO_SUBDIRS:
		subdir_name[0] = 0;
		break;

	case DIR_ROUND_ROBIN:
		if (num_per_subdir) {
			/*
			 * Stick the specified number of files in each directory before 
			 * moving on.
			 */
			if (files_in_subdir >= num_per_subdir) {
				current_subdir++;
				files_in_subdir = 0;
			}
			current_subdir = current_subdir % num_subdirs;
			files_in_subdir++;
		}
		sprintf(subdir_name, "%02x", current_subdir);
		break;

	case DIR_TIME_HASH:
		if ((sec_time - start_sec_time) > secs_per_directory) {
			current_subdir = (current_subdir + 1) % num_subdirs;
			start_sec_time = sec_time;
		}
		sprintf(subdir_name, "%02x", current_subdir);
		break;

	default:
		fprintf(stderr, "fs_mark: invalid directory policy\n");
		exit(1);
		break;
	}

	sprintf(names[file_index].target_dir, "%s/%s", my_dir, subdir_name);

	/*
	 * Make the base directory entry (i.e., /mnt/1/test/00)
	 */
	if ((mkdir(names[file_index].target_dir, 0777) != 0)
	    && (errno != EEXIST)) {
		// fprintf(stderr, "fs_mark: mkdir %s failed: %s\n",
		// 	names[file_index].target_dir, strerror(errno));
		// cleanup_exit();
    // printf("mkdir failed??? target_dir:%s, errno: %d\n", names[file_index].target_dir, errno);
	}

	sprintf(names[file_index].write_dir, "%s", names[file_index].target_dir);

	/*
	 * Set up the sequential name for this file
	 */
	sprintf(seq_name, "%lx", sec_time);

	/*
	 * Compute a random name for the file
	 */
	for (j = 0; j < rand_len; j++) {
		/*
		 * Pick a random name, making sure that it is either a letter or digit
		 */
		do {
			long int val;

			val = random();
			rand_name[j] = '0' + (val & 0x7f);
		} while (!(isupper(rand_name[j]) || isdigit(rand_name[j])));
	}
	rand_name[rand_len] = 0;	/* Terminate string with NULL */

	/*
	 * We want to create names with the specified number of sequential & random bytes.
	 * Make sure to take the least signficant bytes of sequential (the most signficant
	 * do not change)
	 */
	skip = strlen(seq_name) - seq_len;
	if (skip > 0) {		/* More sequential bytes than we need */
		strncat(names[file_index].f_name, &seq_name[skip], seq_len);
	} else {
		strncat(names[file_index].f_name, seq_name, seq_len);
	}
	pad = seq_len - strlen(seq_name);
	for (j = 0; j < pad; j++)
		strcat(names[file_index].f_name, "~");
	strncat(names[file_index].f_name, rand_name, rand_len);

	return;
}

/*
 * Setup and initial state
 */
void setup(pid_t pid)
{
	char thread_log_file_name[PATH_MAX];
	char *my_dir;
	struct timeval now;

	/*
	 * Initialize the random functions for this program.
	 */
	(void)gettimeofday(&now, (struct timezone *)0);
	srandom((long)now.tv_usec);

	if (num_subdirs > 0) {
		/*
		 * Pick a starting directory to write into.
		 * To avoid having short runs always write into the first
		 * few directories, pick a starting directory based on the time value.
		 */
		current_subdir = now.tv_sec % num_subdirs;
	}

	/*
	 * Open the log file in append mode to preserve previous runs data
	 */
	sprintf(thread_log_file_name, "%s.%d", log_file_name, pid);
	if ((child_log_file_fp = fopen(thread_log_file_name, "w")) == NULL) {
		fprintf(stderr,
			"fs_mark:  setup failed to fopen log file: %s %s\n",
			thread_log_file_name, strerror(errno));
		cleanup_exit();
	}

	/*
	 * Clear the io_buffer
	 */
	memset(io_buffer, 0, io_buffer_size);

	/*
	 * Create my high level test directory
	 */
	my_dir = find_dir_name(pid);

	if ((mkdir(my_dir, 0777) != 0) && (errno != EEXIST)) {
		// fprintf(stderr,
		// 	"fill_dir:mkdir %s failed: %s, errno: %d\n", my_dir, errno,
		// 	strerror(errno));
		// cleanup_exit();
    // printf("mkdir failed?: my_dir: %s, errno: %d\n", my_dir, errno);
	}

	return;
}

/*
 * Return an integer to represent the %full (similar hopefully to what df returns!)
 */
int get_df_full(char *dir_name)
{
	struct statfs fs_buf;
	float df_used, used_blocks;
	int df_percent_used;

	if (statfs(dir_name, &fs_buf) == -1) {
		fprintf(stderr, "fs_mark: statfs failed on %s %s\n", dir_name,
			strerror(errno));
		cleanup_exit();
	}

	used_blocks = (float)(fs_buf.f_blocks - fs_buf.f_bavail);

	df_used = (used_blocks / fs_buf.f_blocks);

	df_percent_used = (int)(100 * df_used);

	return (df_percent_used);
}

/*
 * Return an unsigned long long with number of bytes left in file system.
 */
unsigned long long get_bytes_free(char *dir_name)
{
	struct statfs fs_buf;
	unsigned long long bytes_free;

	if (statfs(dir_name, &fs_buf) == -1) {
		fprintf(stderr, "fs_mark: statfs failed on %s %s\n", dir_name,
			strerror(errno));
		cleanup_exit();
	}

	bytes_free = (unsigned long long)fs_buf.f_bavail;
	bytes_free = bytes_free * fs_buf.f_bsize;

	return (bytes_free);
}

/*
 * This routine opens, writes the amount of (zero filled) data to a file.
 * It chunks IO requests into the specified buffer size.  The data is just zeroed, 
 * nothing in the kernel inspects the contents of the buffer on its way to disk.
 */
void write_file(int fd,
		int sz,
		unsigned long long *avg_write_usec,
		unsigned long long *total_write_usec,
		unsigned long long *min_write_usec,
		unsigned long long *max_write_usec)
{
	int ret = 0;
	int sz_left;
	int write_size, write_calls;
	unsigned long long local_write_usec, delta;

	write_calls = 0;
	write_size = io_buffer_size;
	sz_left = sz;
	local_write_usec = 0ULL;

	do {
		if (write_size > sz_left)
			write_size = sz_left;

		start(0);
		if ((ret = write(fd, io_buffer, write_size)) != write_size) {
			fprintf(stderr,
				"fs_mark: write_file write failed: %d %s\n",
				ret, strerror(errno));
			cleanup_exit();
		}
		delta = stop(0, 0);

		local_write_usec += delta;

		if (delta > *max_write_usec)
			*max_write_usec = delta;

		if ((*min_write_usec == 0) || (delta < *min_write_usec))
			*min_write_usec = delta;

		sz_left -= ret;
		write_calls++;
	} while (sz_left > 0);

	*avg_write_usec += (local_write_usec / write_calls);
	*total_write_usec += local_write_usec;

	return;
}

/*
 * Verify that there is enough space for this run.
 */
static void check_space(pid_t my_pid)
{
	char *my_dir_name;
	unsigned long long bytes_per_loop;

	my_dir_name = find_dir_name(my_pid);

	/*
	 * No use in running this if the file system is already full.
	 * Compute free bytes and compare to many bytes needed for this iteration.
	 */
	bytes_per_loop = (unsigned long long)file_size *num_files;
	if (get_bytes_free(my_dir_name) < bytes_per_loop) {
		fprintf(stdout,
			"Insufficient free space in %s to create %d new files, exiting\n",
			my_dir_name, num_files);
		do_fill_fs = 0;	/* Setting this signals the main loop to exit */
		cleanup_exit();
	}

	return;
}

/*
 * Main loop in program - creates, writes and removes "num_files" files of each size. 
 * Each of the subcomponents is measured separately so we can track how specific aspects 
 * degrade.
 */
static struct timeval loop_start_tv, loop_stop_tv;

void do_run(pid_t my_pid)
{
	int file_index, fd;
	float files_per_sec;
	unsigned long long total_file_ops, delta, loop_usecs;
	unsigned long long creat_usec, max_creat_usec, min_creat_usec;
	unsigned long long avg_write_usec, max_write_usec, min_write_usec,
	    total_write_usec;
	unsigned long long fsync_usec, max_fsync_usec, min_fsync_usec;
	unsigned long long close_usec, max_close_usec, min_close_usec;
	unsigned long long unlink_usec, max_unlink_usec, min_unlink_usec;
	unsigned long long avg_sync_usec, app_overhead_usec;
	char file_write_name[MAX_NAME_PATH + FILENAME_SIZE];
	char file_target_name[MAX_NAME_PATH + FILENAME_SIZE];

	/*
	 * Verify that there is enough space for this run.
	 */
	check_space(my_pid);

	/*
	 * This loop uses microsecond timers to measure each individual file operation.
	 * Once all files of a given size have been processed, the sum of the times are 
	 * recorded in operations/sec.
	 */
	files_per_sec = 0.0;
	creat_usec = max_creat_usec = min_creat_usec = 0ULL;
	avg_write_usec = max_write_usec = min_write_usec = total_write_usec = 0ULL;
	fsync_usec = max_fsync_usec = min_fsync_usec = avg_sync_usec = 0ULL;
	close_usec = max_close_usec = min_close_usec = 0ULL;
	unlink_usec = max_unlink_usec = min_unlink_usec = 0ULL;

	/*
	 * MAIN FILE WRITE LOOP:
	 * This loop measures the specific steps in creating files:
	 *      Step 1: Make up a file name
	 *      Step 2: Creat(file_name);
	 *      Step 3: write file data
	 *      Step 4: fsync() file data (optional)
	 *      Step 5: close() file descriptor
	 */

	start(&loop_start_tv);
	for (file_index = 0; file_index < num_files; ++file_index) {
		/*
		 * To better mimic a running system, create the file names here during the run.
		 * This lets us stick in the time of day and vary the distribution in interesting
		 * ways across the directories.
		 * Note: the file name is a full path, so it specifies both the directory and 
		 * filename with the directory.
		 */
		setup_file_name(file_index, my_pid);

		/*
		 * Time the creation of the file.
		 */
		sprintf(file_write_name, "%s/%s", names[file_index].write_dir,
			names[file_index].f_name);
		sprintf(file_target_name, "%s/%s", names[file_index].target_dir,
			names[file_index].f_name);

		start(0);
		if ((fd =
		     open(file_write_name, O_CREAT | O_RDWR | O_TRUNC,
			  0666)) == -1) {
			fprintf(stderr, "Error in creat: %s\n",
				strerror(errno));
			cleanup_exit();
		}
		delta = stop(0, 0);
		creat_usec += delta;

		if (delta > max_creat_usec)
			max_creat_usec = delta;

		if ((min_creat_usec == 0) || (delta < min_creat_usec))
			min_creat_usec = delta;

		/*
		 * Time writing data into the file.
		 * The timing needs to be done inside the subroutine since
		 * one file requires many writes.
		 * In avg_write_usec, we acculumate the average of the average write times.
		 * In total_write_usec, we track the total time spent in write().
		 */
		write_file(fd, file_size, &avg_write_usec, &total_write_usec,
			   &min_write_usec, &max_write_usec);

		/*
		 * Time the fsync() operation.
		 * With the write barrier patch in the kernel,
		 * this actually flushed the IDE write cache as well.
		 */
		if (sync_method & FSYNC_BEFORE_CLOSE) {
			start(0);

			if (fsync(fd) == -1) {
				fprintf(stderr, "fs_mark: fsync failed %s\n",
					strerror(errno));
				cleanup_exit();
			}
			delta = stop(0, 0);
			fsync_usec += delta;

			if (delta > max_fsync_usec)
				max_fsync_usec = delta;
			if ((min_fsync_usec == 0) || (delta < min_fsync_usec))
				min_fsync_usec = delta;
		}

		/*
		 * Time the file close
		 */
		start(0);
		close(fd);
		delta = stop(0, 0);

		close_usec += delta;
		if (delta > max_close_usec)
			max_close_usec = delta;

		if ((min_close_usec == 0) || (delta < min_close_usec))
			min_close_usec = delta;

	}

	if (sync_method & FSYNC_SYNC_SYSCALL) {
		start(0);
		sync();
		delta = stop(0, 0);

		/*
		 * Add the time spent in sync() to the total cost of fsync()
		 */
		avg_sync_usec = delta;
	}

	/*
	 * Post writing, in order fsync method.
	 * Note that we count three system calls into the time spent in fsync() here -
	 * the open/fsync and close.
	 */
	if (sync_method & FSYNC_POST_IN_ORDER) {
		for (file_index = 0; file_index < num_files; ++file_index) {
			int fd;

			sprintf(file_target_name, "%s/%s",
				names[file_index].target_dir,
				names[file_index].f_name);

			start(0);
			if ((fd = open(file_target_name, O_RDONLY, 0666)) == -1) {
				fprintf(stderr, "Error in open of %s : %s\n",
					file_target_name, strerror(errno));
				cleanup_exit();
			}

			if (fsync(fd) == -1) {
				fprintf(stderr, "fs_mark: fsync failed %s\n",
					strerror(errno));
				cleanup_exit();
			}

			close(fd);
			delta = stop(0, 0);
			fsync_usec += delta;

			if (delta > max_fsync_usec)
				max_fsync_usec = delta;
			if ((min_fsync_usec == 0) || (delta < min_fsync_usec))
				min_fsync_usec = delta;
		}
	}

	/*
	 * Post writing, reverse order fsync method.
	 * Note that we count three system calls into the time spent in fsync() here -
	 * the open/fsync and close.
	 */
	if (sync_method & FSYNC_POST_REVERSE) {
		for (file_index = (num_files - 1); file_index >= 0;
		     --file_index) {
			int fd;

			sprintf(file_target_name, "%s/%s",
				names[file_index].target_dir,
				names[file_index].f_name);

			start(0);
			if ((fd = open(file_target_name, O_RDONLY, 0666)) == -1) {
				fprintf(stderr, "Error in open of %s : %s\n",
					file_target_name, strerror(errno));
				cleanup_exit();
			}

			if (fsync(fd) == -1) {
				fprintf(stderr, "fs_mark: fsync failed %s\n",
					strerror(errno));
				cleanup_exit();
			}

			close(fd);
			delta = stop(0, 0);
			fsync_usec += delta;

			if (delta > max_fsync_usec)
				max_fsync_usec = delta;
			if ((min_fsync_usec == 0) || (delta < min_fsync_usec))
				min_fsync_usec = delta;

		}
	}

	/*
	 * Post writing, one per directory fsync method.
	 * Note that we count three system calls into the time spent in fsync() here -
	 * the open/fsync and close.
	 */
	if (sync_method & FSYNC_FIRST_FILE) {
		int fd;

		sprintf(file_target_name, "%s/%s", names[0].target_dir,
			names[0].f_name);

		start(0);
		if ((fd = open(file_target_name, O_RDONLY, 0666)) == -1) {
			fprintf(stderr, "Error in open of %s : %s\n",
				file_target_name, strerror(errno));
			cleanup_exit();
		}

		if (fsync(fd) == -1) {
			fprintf(stderr, "fs_mark: fsync failed %s\n",
				strerror(errno));
			cleanup_exit();
		}

		close(fd);
		fsync_usec += stop(0, 0);
	}

	/*
	 * Record the total time spent in the file writing loop - we ignore the time spent unlinking files
	 */
	loop_usecs = stop(&loop_start_tv, &loop_stop_tv);

	/*
	 * Time unlink of the file if files need removing for this run.
	 */
	if (!keep_files) {
		for (file_index = 0; file_index < num_files; ++file_index) {
			sprintf(file_target_name, "%s/%s",
				names[file_index].target_dir,
				names[file_index].f_name);

			start(0);
			if (unlink(file_target_name) == -1) {
				fprintf(stderr, "Error in unlink of %s : %s\n",
					file_target_name, strerror(errno));
				cleanup_exit();
			}
			delta = stop(0, 0);

			unlink_usec += delta;
			if (delta > max_unlink_usec)
				max_unlink_usec = delta;

			if ((min_unlink_usec == 0) || (delta < min_unlink_usec))
				min_unlink_usec = delta;
		}
	}

	/*
	 * Combine the file write operations into one metric
	 */
	total_file_ops =
	    creat_usec + total_write_usec + fsync_usec + avg_sync_usec +
	    close_usec;
	app_overhead_usec = loop_usecs - total_file_ops;

	/*
	 * Keep track of how many total files we have written since the program
	 * started
	 */
	file_count += num_files;

	/*
	 * Now compute the rate that we wrote files in files/sec.
	 */
	files_per_sec = num_files / (loop_usecs / 1000000.0);

	/*
	 * Write to the log file.
	 */
	fprintf(child_log_file_fp,
		"%u %.1f %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu\n",
		file_count,
		files_per_sec,
		app_overhead_usec,
		min_creat_usec,
		creat_usec / num_files,
		max_creat_usec,
		min_write_usec,
		avg_write_usec / num_files,
		max_write_usec,
		min_fsync_usec,
		fsync_usec / num_files,
		max_fsync_usec,
		avg_sync_usec,
		min_close_usec,
		close_usec / num_files,
		max_close_usec,
		min_unlink_usec, unlink_usec / num_files, max_unlink_usec);

	fflush(child_log_file_fp);

	return;
}

void process_child_log_file(pid_t child_pid, fs_mark_stat_t * thread_stats)
{
	char child_log_file_name[PATH_MAX];
	FILE *thread_log_fp;
	int res;

	/*
	 * Compute and open the child thread log file
	 */
	sprintf(child_log_file_name, "%s.%d", log_file_name, child_pid);
	if ((thread_log_fp = fopen(child_log_file_name, "r")) == NULL) {
		fprintf(stderr, "fopen failed to open: %s\n",
			child_log_file_name);
		cleanup_exit();
	}

	if ((res = fscanf(thread_log_fp,
			  "%u %f %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu",
			  &thread_stats->file_count,
			  &thread_stats->files_per_sec,
			  &thread_stats->app_overhead_usec,
			  &thread_stats->min_creat_usec,
			  &thread_stats->avg_creat_usec,
			  &thread_stats->max_creat_usec,
			  &thread_stats->min_write_usec,
			  &thread_stats->avg_write_usec,
			  &thread_stats->max_write_usec,
			  &thread_stats->min_fsync_usec,
			  &thread_stats->avg_fsync_usec,
			  &thread_stats->max_fsync_usec,
			  &thread_stats->avg_sync_usec,
			  &thread_stats->min_close_usec,
			  &thread_stats->avg_close_usec,
			  &thread_stats->max_close_usec,
			  &thread_stats->min_unlink_usec,
			  &thread_stats->avg_unlink_usec,
			  &thread_stats->max_unlink_usec)) != 19) {
		fprintf(stderr,
			"fscanf read too few entries from thread log file: %s\n",
			child_log_file_name);
		cleanup_exit();
	}

	/*
	 * Close & remove the thread log file
	 */
	fclose(thread_log_fp);
	unlink(child_log_file_name);

	return;
}

/*
 * Add the thread_stats information into the global iteration statistics
 */
void aggregate_thread_stats(fs_mark_stat_t * thread_stats,
			    fs_mark_stat_t * iteration_stats)
{
	int i;

	for (i = 0; i < num_threads; i++) {
		process_child_log_file(child_tasks[i].child_pid, thread_stats);

		/*
		 * File count and files/second are simple additions
		 */
		iteration_stats->file_count += thread_stats->file_count;
		iteration_stats->files_per_sec += thread_stats->files_per_sec;
		iteration_stats->app_overhead_usec +=
		    thread_stats->app_overhead_usec;

		/*
		 * For each of the measured system calls, sum up the average times and
		 * compute the min and max.
		 * We divide the averages after this loop by thread count.
		 */
		iteration_stats->avg_creat_usec += thread_stats->avg_creat_usec;
		if ((iteration_stats->min_creat_usec == 0) ||
		    (thread_stats->min_creat_usec <
		     iteration_stats->min_creat_usec))
			iteration_stats->min_creat_usec =
			    thread_stats->min_creat_usec;
		if (thread_stats->max_creat_usec >
		    iteration_stats->max_creat_usec)
			iteration_stats->max_creat_usec =
			    thread_stats->max_creat_usec;

		iteration_stats->avg_write_usec += thread_stats->avg_write_usec;
		if ((iteration_stats->min_write_usec == 0) ||
		    (thread_stats->min_write_usec <
		     iteration_stats->min_write_usec))
			iteration_stats->min_write_usec =
			    thread_stats->min_write_usec;
		if (thread_stats->max_write_usec >
		    iteration_stats->max_write_usec)
			iteration_stats->max_write_usec =
			    thread_stats->max_write_usec;

		iteration_stats->avg_fsync_usec += thread_stats->avg_fsync_usec;
		if ((iteration_stats->min_fsync_usec == 0) ||
		    (thread_stats->min_fsync_usec <
		     iteration_stats->min_fsync_usec))
			iteration_stats->min_fsync_usec =
			    thread_stats->min_fsync_usec;
		if (thread_stats->max_fsync_usec >
		    iteration_stats->max_fsync_usec)
			iteration_stats->max_fsync_usec =
			    thread_stats->max_fsync_usec;

		iteration_stats->avg_sync_usec += thread_stats->avg_sync_usec;
		if ((iteration_stats->min_sync_usec == 0) ||
		    (thread_stats->min_sync_usec <
		     iteration_stats->min_sync_usec))
			iteration_stats->min_sync_usec =
			    thread_stats->min_sync_usec;
		if (thread_stats->max_sync_usec >
		    iteration_stats->max_sync_usec)
			iteration_stats->max_sync_usec =
			    thread_stats->max_sync_usec;

		iteration_stats->avg_close_usec += thread_stats->avg_close_usec;
		if ((iteration_stats->min_close_usec == 0) ||
		    (thread_stats->min_close_usec <
		     iteration_stats->min_close_usec))
			iteration_stats->min_close_usec =
			    thread_stats->min_close_usec;
		if (thread_stats->max_close_usec >
		    iteration_stats->max_close_usec)
			iteration_stats->max_close_usec =
			    thread_stats->max_close_usec;

		iteration_stats->avg_unlink_usec +=
		    thread_stats->avg_unlink_usec;
		if ((iteration_stats->min_unlink_usec == 0)
		    || (thread_stats->min_unlink_usec <
			iteration_stats->min_unlink_usec))
			iteration_stats->min_unlink_usec =
			    thread_stats->min_unlink_usec;
		if (thread_stats->max_unlink_usec >
		    iteration_stats->max_unlink_usec)
			iteration_stats->max_unlink_usec =
			    thread_stats->max_unlink_usec;
	}

	/*
	 * Recompute the avgerage "average" of the per thread times
	 */
	if (num_threads > 1) {
		iteration_stats->avg_creat_usec =
		    iteration_stats->avg_creat_usec / num_threads;
		iteration_stats->avg_write_usec =
		    iteration_stats->avg_write_usec / num_threads;
		iteration_stats->avg_fsync_usec =
		    iteration_stats->avg_fsync_usec / num_threads;
		iteration_stats->avg_sync_usec =
		    iteration_stats->avg_sync_usec / num_threads;
		iteration_stats->avg_close_usec =
		    iteration_stats->avg_close_usec / num_threads;
		iteration_stats->avg_unlink_usec =
		    iteration_stats->avg_unlink_usec / num_threads;
	}

	return;
}

/*
 * Simple wrapper for the per thread work routines.
 */
void thread_work(pid_t my_pid)
{

	/*
	 * Do any initialization
	 */
	setup(my_pid);

	do_run(my_pid);

	fclose(child_log_file_fp);
}

/*
 * This routine is used only when running more than one thread (done whenever writing to
 * more than one directory).
 * Fork each of the required threads and then wait on their exit status.
 */

void single_threads() {
  child_tasks[0].child_pid = getpid();
  thread_work(child_tasks[0].child_pid);
  // exit(0);
}

void fork_threads(void)
{
	int i, active_kids = 0;

	/*
	 * Clear out any pending writes before the fork so we don't get duplication
	 */
	fflush(stdout);
	fflush(log_file_fp);

	/*
	 * Fork one thread for each of the specified children
	 */

	for (i = 0; i < num_threads; i++) {
		if ((child_tasks[i].child_pid = fork()) == -1) {
			fprintf(stderr, "fs_mark: fork failed: %s\n",
				strerror(errno));
			cleanup_exit();
		}
		if (child_tasks[i].child_pid == 0) {

			/*
			 * Child thread: Set my real pid in the array and
			 * then do work.
			 */
			child_tasks[i].child_pid = getpid();
			thread_work(child_tasks[i].child_pid);

			/*
			 * My work is done, exit to let parent thread reap my state
			 */
			exit(0);
		}
		active_kids++;
	}

	/*
	 * Parent thread: Wait for each of the child threads to exit
	 */
	while (active_kids) {
		int status;
		pid_t child_pid;

		/*
		 * Wait until child exits. Note that we need to loop on interrupts (this 
		 * happens in gdb, etc).
		 */
		child_pid = wait(&status);
		if (child_pid == -1) {
			if (errno == EINTR)
				continue;
			fprintf(stderr, "fs_mark: wait failed: %s\n",
				strerror(errno));
			exit(0);
		}

		/*
		 * Check that this was the clean exit of one of our threads
		 */
		for (i = 0; i < num_threads; i++) {
			if (child_tasks[i].child_pid == child_pid) {
				active_kids--;
				break;
			}
		}
	}
	return;
}

/*
 * Print some test information and basic parameters to help user understand the rather complex options.
 */
void print_run_info(FILE * log_fp, int argc, char **argv)
{
	// time_t time_run;
	int i;

	// time_run = time(0);
	fprintf(log_fp, "\n# ");
	for (i = 0; i < argc; i++)
		fprintf(log_fp, " %s ", argv[i]);
	fprintf(log_fp, "\n#\tVersion %s, %d thread(s) starting at %s",
		fs_mark_version, num_threads, "dummy time\n");
	fprintf(log_fp, "#\tSync method: %s\n",
		sync_policy_string[sync_method_type]);
	if (num_subdirs > 1) {
		fprintf(log_fp,
			"#\tDirectories:  %s across %d subdirectories with %d %s.\n",
			dir_policy_string[dir_policy], num_subdirs,
			dir_policy ==
			DIR_ROUND_ROBIN ? num_per_subdir : (int) secs_per_directory,
			dir_policy == DIR_ROUND_ROBIN ? "files per subdirectory" :
			"seconds per subdirectory");
	} else
		fprintf(log_fp, "#\tDirectories:  no subdirectories used\n");
	fprintf(log_fp,
		"#\tFile names: %d bytes long, (%d initial bytes of time stamp with %d random bytes at end of name)\n",
		name_len, name_len - rand_len, rand_len);
	fprintf(log_fp,
		"#\tFiles info: size %d bytes, written with an IO size of %d bytes per write\n",
		file_size, io_buffer_size);
	fprintf(log_fp,
		"#\tApp overhead is time in microseconds spent in the test not doing file writing related system calls.\n");

	if (log_fp != stdout)
		fprintf(log_fp, "#");
	if (verbose_stats) {
		fprintf(log_fp,
			"#\tAll system call times are reported in microseconds.\n\n");
		fprintf(log_fp,
			"%6s %12s %12s %12s %16s %26s %26s %26s %26s %26s %26s\n",
			"FSUse%", "Count", "Size", "Files/sec", "App Overhead",
			"CREAT (Min/Avg/Max)", "WRITE (Min/Avg/Max)",
			"FSYNC (Min/Avg/Max)", "SYNC (Min/Avg/Max)",
			"CLOSE (Min/Avg/Max)", "UNLINK (Min/Avg/Max)");
	} else {
		fprintf(log_fp, "\n");
		fprintf(log_fp, "%6s %12s %12s %12s %16s\n",
			"FSUse%", "Count", "Size", "Files/sec", "App Overhead");
	}

	return;
}

/*
 * Keep this routine's stdout logging coordinated with the logging done above
 * in print_run_info().
 */
void print_iteration_stats(FILE * log_fp, fs_mark_stat_t * iteration_stats,
			   unsigned int files_written)
{
	int df_full;

	/*
	 * Check how full the first directory is after each run
	 */
	df_full = get_df_full(child_tasks[0].test_dir);

	if (verbose_stats)
		fprintf(log_fp,
			"%6u %12u %12u %12.1f %16llu %8llu %8llu %8llu %8llu %8llu %8llu %8llu %8llu %8llu %8llu %8llu %8llu %8llu %8llu %8llu %8llu %8llu %8llu\n",
			df_full,
			files_written,
			file_size,
			iteration_stats->files_per_sec,
			iteration_stats->app_overhead_usec,
			iteration_stats->min_creat_usec,
			iteration_stats->avg_creat_usec,
			iteration_stats->max_creat_usec,
			iteration_stats->min_write_usec,
			iteration_stats->avg_write_usec,
			iteration_stats->max_write_usec,
			iteration_stats->min_fsync_usec,
			iteration_stats->avg_fsync_usec,
			iteration_stats->max_fsync_usec,
			iteration_stats->min_sync_usec,
			iteration_stats->avg_sync_usec,
			iteration_stats->max_sync_usec,
			iteration_stats->min_close_usec,
			iteration_stats->avg_close_usec,
			iteration_stats->max_close_usec,
			iteration_stats->min_unlink_usec,
			iteration_stats->avg_unlink_usec,
			iteration_stats->max_unlink_usec);
	else
		fprintf(log_fp,
			"%6u %12u %12u %12.1f %16llu\n",
			df_full,
			files_written,
			file_size,
			iteration_stats->files_per_sec,
			iteration_stats->app_overhead_usec);

	fflush(log_fp);
	return;
}

static int interrupted = 0;
static void handle_sigint(int sig, siginfo_t *siginfo, void *context)
{
	interrupted = 1;
}

/*
 * This does the reverse sort because we want to do the percentiles to show how
 * slow we could be going.
 */
static int cmp(const void *p1, const void *p2)
{
	unsigned long long a = *(unsigned long long *)p1;
	unsigned long long b = *(unsigned long long *)p2;

	if (a > b)
		return -1;
	else if (a < b)
		return 1;
	return 0;
}

int main(int argc, char **argv, char **envp)
{
	unsigned int files_written = 0;
	unsigned int loops_done = 0;
	unsigned long long *files_per_sec;
	unsigned long long files_per_sec_sum = 0;
	unsigned nr_iters = 0;
	struct sigaction act;

	process_args(argc, argv, envp);

  double start_time = second();
  printf("start_time: %f\n", start_time);

	/*
	 * Open the specified log file - at the end, each child's log file will be written out to this one.
	 * Note that each child uses its copy of this fp for its own sub log file.
	 */
	if ((log_file_fp = fopen(log_file_name, "a")) == NULL) {
		fprintf(stderr,
			"fs_mark: failed to fopen log file: %s %s\n",
			log_file_name, strerror(errno));
		cleanup_exit();
	}

	memset(&act, 0, sizeof(act));
	act.sa_sigaction = &handle_sigint;
	act.sa_flags = SA_SIGINFO;

	if (sigaction(SIGINT, &act, NULL) < 0) {
		perror("sigaction");
		cleanup_exit();
	}

	/*
	 * Print some information about this test run
	 */
	print_run_info(stdout, argc, argv);
	print_run_info(log_file_fp, argc, argv);

	files_per_sec = (unsigned long long *) malloc(sizeof(unsigned long long));
	if (!files_per_sec) {
		perror("malloc");
		cleanup_exit();
	}

	/*
	 * This is the main loop of the program - we loop here until
	 * the file system is full when running in "-F" fill mode
	 */
	do {
		fs_mark_stat_t thread_stats, iteration_stats;

		memset(&thread_stats, 0, sizeof(thread_stats));
		memset(&iteration_stats, 0, sizeof(iteration_stats));

		// fork_threads();
    single_threads();

		/*
		 * Each child thread has produced one line of output in its log file.
		 * This merges the individual lines from these files into the master logfile 
		 * and writes the result to stdout.
		 */
		aggregate_thread_stats(&thread_stats, &iteration_stats);

		/*
		 * Track how many files have been written
		 */
		files_written += iteration_stats.file_count;

		if (loops_done > 0) {
			files_per_sec = (unsigned long long *)realloc(files_per_sec,
					       sizeof(unsigned long long) *
					       (nr_iters + 1));
			if (!files_per_sec) {
				perror("realloc");
				cleanup_exit();
			}
		}

		files_per_sec[nr_iters] = iteration_stats.files_per_sec;
		files_per_sec_sum += iteration_stats.files_per_sec;
		nr_iters++;

		print_iteration_stats(stdout, &iteration_stats, files_written);
		print_iteration_stats(log_file_fp, &iteration_stats,
				      files_written);
		loops_done++;

	} while ((do_fill_fs || (loop_count > loops_done)) && !interrupted);

	qsort(files_per_sec, nr_iters, sizeof(unsigned long long), cmp);

	printf("Average Files/sec: %12.1f\n",
	       (float)files_per_sec_sum / nr_iters);
	printf("p50 Files/sec: %llu\n", files_per_sec[nr_iters / 2]);
	printf("p90 Files/sec: %llu\n", files_per_sec[(nr_iters * 9) / 10]);
	printf("p99 Files/sec: %llu\n", files_per_sec[(nr_iters * 99) / 100]);

  double end_time = second();
  printf("end_time: %f\n", end_time);
  printf("measurement time: %f\n", end_time - start_time);

	return (0);
}
