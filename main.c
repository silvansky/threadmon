//
//  main.c
//  threadmon
//
//  Created by V. Silvansky on 25/09/2012.
//  Copyright (c) 2012 V. Silvansky. All rights reserved.
//
// This software is distributed under GPLv3 licence.
// See COPYING for more information.
//


#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <mach/mach.h>
#include <errno.h>
#include <stdlib.h>

#include <Security/Authorization.h>

#define STATUS_SUCCESS             0
#define STATUS_ERR_NO_ARGS        -1
#define STATUS_ERR_INVALID_PID    -2
#define STATUS_ERR_TASK_FOR_PID   -3
#define STATUS_ERR_TASK_THREADS   -4

int acquireTaskportRight()
{
	OSStatus stat;
	AuthorizationItem taskport_item[] = {{"system.privilege.taskport:"}};
	AuthorizationRights rights = {1, taskport_item}, *out_rights = NULL;
	AuthorizationRef author;

	AuthorizationFlags auth_flags = kAuthorizationFlagExtendRights | kAuthorizationFlagPreAuthorize | kAuthorizationFlagInteractionAllowed | ( 1 << 5);

	stat = AuthorizationCreate(NULL, kAuthorizationEmptyEnvironment, auth_flags, &author);
	if (stat != errAuthorizationSuccess)
	{
		return 1;
	}

	stat = AuthorizationCopyRights(author, &rights, kAuthorizationEmptyEnvironment, auth_flags, &out_rights);
	if (stat != errAuthorizationSuccess)
	{
		return 1;
	}
	return 0;
}

int main(int argc, char *argv[])
{
	if (argc != 2)
	{
		printf("Usage:\n    %s <PID>\n", argv[0]);
		return STATUS_ERR_NO_ARGS;
	}

	if (acquireTaskportRight())
	{
		printf("No rights granted by user or some error occured! Terminating.\n");
		return 0;
	}

	char* end;
	pid_t pid = strtol(argv[1], &end, 10);
	if (*end)
	{
		printf("Error: invalid PID given: \"%s\", terminating.\n", argv[1]);
		return STATUS_ERR_INVALID_PID;
	}

	printf("Starting threadmon for PID %d\n", pid);

	task_t port;
	kern_return_t kr = task_for_pid(mach_task_self(), pid, &port);
	if (kr != KERN_SUCCESS)
	{
		printf("task_for_pid() returned %d, terminating.\n", kr);
		return STATUS_ERR_TASK_FOR_PID;
	}

	thread_array_t thread_list;
	mach_msg_type_number_t thread_count;

	thread_info_data_t thinfo;
	mach_msg_type_number_t thread_info_count;

	thread_basic_info_t basic_info_th;

	// get threads in the task
	kr = task_threads(port, &thread_list, &thread_count);
	if (kr != KERN_SUCCESS)
	{
		printf("task_threads() returned %d, terminating.\n", kr);
		return STATUS_ERR_TASK_THREADS;
	}

	long tot_cpu = 0;
	int j;

	for (j = 0; j < thread_count; j++)
	{
		thread_info_count = THREAD_INFO_MAX;
		kr = thread_info(thread_list[j], THREAD_BASIC_INFO, (thread_info_t)thinfo, &thread_info_count);
		if (kr != KERN_SUCCESS)
		{
			printf("Thread %d: Error %d\n", thread_list[j], kr);
			continue;
		}
		basic_info_th = (thread_basic_info_t)thinfo;

		if (!(basic_info_th->flags & TH_FLAGS_IDLE))
		{
			tot_cpu = tot_cpu + basic_info_th->cpu_usage;
			printf("Thread %d: CPU %d%%\n", thread_list[j], basic_info_th->cpu_usage);
		}
	}
	printf("---\nTotal: CPU %ld%%\n", tot_cpu);
	return STATUS_SUCCESS;
}
