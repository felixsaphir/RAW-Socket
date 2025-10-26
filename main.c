/*
 * Project - IP Sniffer
 *
 *  Created on: Aug 5, 2018
 *      Author: Yoram Finder
 *
 *  Demo program that shows how to open RAW IP socket on WINDOWS 10 using MINGW_W64 compiler.
 *  Capture all IP frames, list the IP, TCP, UDP and ICMP headers and the rest of the message payload.
 *
 *  The program uses the semaphore and pthread libraries to allow one thread to be reasponsile for capturing the
 *  network traffic, while the other thread to print them on screen. This allows the program to hanlde high traffic
 *  load regradless of the slow output.
 *
 *  This small project is an attempt from my side to return to programming after more than 20 years. What can be a better
 *  language to return to than C ?
 *
 *  The program recieves two parameters IP_Add Duration
 *    IP_Add - local IP address of the NW inerface you want to connect to
 *    Duration - time on second to let the program run and capture traffic
 *
 *    (*) This program needs ADMIN privilages to run
 *
 *  All rights reserved.
 */


#include <semaphore.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "Network.h"

#define MAX_BUFF 65*1024
#define MAX_QUEUE 5
#define MAX_COUNT 1000

typedef struct _buff_rec
{
	pthread_mutex_t 	mutex;
	char				empty;
	unsigned int		seq;
	unsigned int		bytes;
	char				*buff;
}  buff_rec;

static buff_rec s_queue [MAX_QUEUE];
static sem_t q_sem;

static int wrt_trd_exit, rd_trd_exit;
static int exit_program = 0;
static char const *trd_name[2] = {"Read trd", "Write trd"};

/* create thread argument struct for thr_func() */
typedef struct _thread_data_t {
  int tid;
  int sock;
  double stuff;
} thread_data_t;

/* Write thread function */
void *write_trd_func(void *arg)
{
	int id;
	int bufflock, buffcnt, mutexloc;
	char internal_buff[MAX_BUFF];
	int s, bytes, sock;
	thread_data_t *parg;

	parg = (thread_data_t *)arg;
	id = parg->tid;
	sock = parg->sock;

	printf("initializing Writing Thread...ID: %d, %s\n", id, trd_name[id]);
	memset(internal_buff, 0, MAX_BUFF);
	bufflock = 0;
	buffcnt = 0;

	while (!exit_program) // loop will exit on next read NW attempt
	{

		if ((bytes = NW_read(sock, internal_buff, MAX_BUFF, 0)) < 0)
		{
			printf("%s, NW read failed, %d\n", trd_name[id], NW_errno);
			wrt_trd_exit = -1;
			exit_program = 1;
			pthread_exit(&wrt_trd_exit);
		}
		buffcnt = ((buffcnt+1)%MAX_COUNT); // continue counting regardless of s_queue updates

		/*
		 * We need to fill the next buffer.
		 * But first check to see if next available buffer is ready - otherwise just dump the new buffer
		 * Since we are accessing shared queue we need to use Mutex to handle the that.
		 */
		mutexloc = bufflock;
		if ((s = pthread_mutex_lock(&s_queue[mutexloc].mutex)) == 0)
		{
			if (s_queue[bufflock].empty == 0)
			{
				s_queue[bufflock].empty = 1;
				s_queue[bufflock].seq = buffcnt;
				s_queue[bufflock].bytes = bytes;
				memcpy(s_queue[bufflock].buff, internal_buff, bytes);

				/*
				 * if reading thread is waiting for semaphore then set it
				 */
				if ((sem_getvalue(&q_sem, &s)) < 0)
				{
					printf("%s, failed to get queue semaphore, %d\n", trd_name[id], errno);
					wrt_trd_exit = -1;
					exit_program = 1;
					pthread_exit(&wrt_trd_exit);
				}
				else if (s < 1)
				{
					if (sem_post(&q_sem) < 0)
					{
						printf("%s, failed to set queue semaphore, %d\n", trd_name[id], errno);
						wrt_trd_exit = -1;
						exit_program = 1;
						pthread_exit(&wrt_trd_exit);
					}

				}

				bufflock = ((bufflock+1)%MAX_QUEUE); // cyclick buffer
			}
			else printf("%s, no empty buffer in queue dump record and releasing mutex\n", trd_name[id]);

			if ((s = pthread_mutex_unlock(&s_queue[mutexloc].mutex)) != 0)
				printf("%s, failed to unlock buffer[%d] in shared queue. Error: %d\n", trd_name[id], bufflock, s);
		}
		else
			printf("%s, failed to lock buffer[%d] in shared queue. Error: %d\n", trd_name[id], bufflock, s);

	}

	/*
	 * got signal to exit thread
	 */
	printf("%s, Thread exiting..\n", trd_name[id]);
	wrt_trd_exit = 1;
	exit_program = 1;
	sem_post(&q_sem); //just in case read thread entered its main loop once again before exit_program was set
	pthread_exit(&wrt_trd_exit);

	return NULL; // just to avoid comple warning. THis function will not reach this point ever!!
}


/* read thread function */
void *read_trd_func(void *arg)
{
	int id, i;
	int bufflock, mutexloc;
	char internal_buff[MAX_BUFF];
	int s;
	thread_data_t *parg;

	parg = (thread_data_t *)arg;
	id = parg->tid;

	printf("initializing Reading Thread...ID: %d, %s\n", id, trd_name[id]);
	memset(internal_buff, 0, MAX_BUFF);
	bufflock = 0;


	while (!exit_program)
	{
		/*
		 * Whait on queue semaphore.
		 */
		if (sem_wait(&q_sem) < 0)
		{
			printf("%s, failed to wait on queue semaphore, %d\n", trd_name[id], errno);
			rd_trd_exit = -1;
			exit_program = 1;
			pthread_exit(&rd_trd_exit);

		}
		/*
		 * We need to fill the next buffer.
		 * But first check to see if next available buffer is ready - otherwise just dump the new buffer
		 * Since we are accessing shared queue we need to use Mutex to handle the that.
		 */
		mutexloc = bufflock;
		if ((s = pthread_mutex_lock(&s_queue[mutexloc].mutex)) == 0)
		{
			if (s_queue[bufflock].empty == 1)
			{
				memcpy(internal_buff, s_queue[bufflock].buff, s_queue[bufflock].bytes);
				printf("\n\nIP Packet (%u)\n", s_queue[bufflock].seq);
				NW_Print_IP(internal_buff, s_queue[bufflock].bytes);
				s_queue[bufflock].empty = 0;
				bufflock = ((bufflock+1)%MAX_QUEUE); // cyclick buffer
			}
			else printf("%s, read buff - not ready - release mutex\n", trd_name[id]);

			if ((s = pthread_mutex_unlock(&s_queue[mutexloc].mutex)) != 0)
				printf("%s, failed to unlock buffer[%d] in shared queue. Error: %d\n", trd_name[id], bufflock, s);
		}
		else
			printf("%s, failed to lock buffer[%d] in shared queue. Error: %d\n", trd_name[id], bufflock, s);
	}

	/*
	 * empty shared buffer
	 */
	printf("%s, printing out remaining of queue....\n", trd_name[id]);
	for (i = 0; i < MAX_QUEUE; i++)
	{
		if (s_queue[bufflock].empty == 1)
		{
			memcpy(internal_buff, s_queue[bufflock].buff, s_queue[bufflock].bytes);
			printf("\n\nIP Packet (%u)\n", s_queue[bufflock].seq);
			NW_Print_IP(internal_buff, s_queue[bufflock].bytes);
			s_queue[bufflock].empty = 0;
			bufflock = ((bufflock+1)%MAX_QUEUE); // cyclick buffer
		}
	}

	/*
	 * got signal to exit thread
	 */
	printf("%s, Thread exiting..\n", trd_name[id]);
	rd_trd_exit = 1;
	exit_program = 1;
	pthread_exit(&rd_trd_exit);

	return NULL; // just to avoid comple warning. THis function will not reach this point ever!!

}

int main (int argc, char *argv[])
{
	thread_data_t rd, wrt;
	pthread_t rd_t, wrt_t;
	int s, i;
	int *trd_exit;

	int	sock;

	char	local_ip[100];
	int	time_s;

	  if (argc < 3)
	  {
		  printf("USage: IPSniffer IP_Add Time\n");
		  printf("IP_add - IP address (x.x.x.x) of the NW interface you want to sniff\n");
		  printf("Time - Sniffing duration in seconds\n");
		  return -1;
	  }
	  sscanf(argv[1], "%s", local_ip);
	  sscanf(argv[2], "%d", &time_s);

	  sock = NW_inint (local_ip);

	rd.tid = 0;
	rd.sock = sock;
	wrt.tid = 1;
	wrt.sock = sock;

	memset(s_queue, 0, MAX_QUEUE*sizeof(buff_rec));


	/*
	 * initialize mutexs and semaphore
	 */
	for (i = 0; i<MAX_QUEUE; i++)
	{
		if ((s_queue[i].buff = (char*)malloc(MAX_BUFF)) == NULL)
		{
			printf("failed to allocate RAM for shared queue. Failed at: %d, error: %d\n", i, errno);
			return -1;
		}
		if ((s = pthread_mutex_init(&s_queue[i].mutex, NULL)) != 0)
		{
			printf("failed to inint mutex (%d), error: %d\n", i, s);
			return -1;
		}
	}

	if ((s = sem_init(&q_sem, 0, 0)) == -1)
	{
		printf("failed to initialized semaphore, error: %d\n", s);
		return -1;
	}


	if ((s = pthread_create(&rd_t, NULL, read_trd_func, &rd)))
	{
	      fprintf(stderr, "error: pthread_create rd, error: %d\n", s);
	      return 0;
	}

	if ((s = pthread_create(&wrt_t, NULL, write_trd_func, &wrt)))
	{
	      fprintf(stderr, "error: pthread_create wrt, error: %d\n", s);
	      return 0;
	}

	printf("Main: going to sleep for %d sec\n", time_s);
	sleep(time_s);
	printf("Main: signal threads to exit\n");
	exit_program = 1;

	pthread_join(rd_t, (void **)&trd_exit);
	printf("Read Tread exit with status: %d\n", *trd_exit);
	pthread_join(wrt_t, (void **)&trd_exit);
	printf("Write Tread exit with status: %d\n", *trd_exit);

	/*
	 * Destroy mutexts and semaphore
	 */
	for (i = 0; i<MAX_QUEUE; i++)
	{
		pthread_mutex_destroy(&s_queue[i].mutex);
		free(s_queue[i].buff);
	}
	sem_destroy(&q_sem);

	NW_close (sock);

	return 1;
}
