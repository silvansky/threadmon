#include <stdio.h> 
#include <unistd.h> 
#include <sys/types.h> 
#include <sys/ptrace.h> 
#include <mach/mach.h> 
#include <errno.h> 
#include <stdlib.h> 

#include <Security/Authorization.h>

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
		return -1;
	}

	if (acquireTaskportRight())
	{
		printf("No rights granted by user or some error occured! Terminating.\n");
		return 0;
	}

	pid_t pid = strtol(argv[1], (char **)NULL, 10);

	printf("Starting threadmon for PID %d\n", pid);

	task_t port;
	task_for_pid(mach_task_self(), pid, &port);

	task_info_data_t tinfo;
	mach_msg_type_number_t task_info_count;

	task_info_count = TASK_INFO_MAX;
	int kr = task_info(port, TASK_BASIC_INFO, (task_info_t)tinfo, &task_info_count);
	if (kr != KERN_SUCCESS)
	{
		printf("task_info() returned %d, terminating.\n", kr);
		return -2;
	}

	task_basic_info_t basic_info;
	thread_array_t thread_list;
	mach_msg_type_number_t thread_count;

	thread_info_data_t thinfo;
	mach_msg_type_number_t thread_info_count;

	thread_basic_info_t basic_info_th;
	uint32_t stat_thread = 0; // Mach threads

	basic_info = (task_basic_info_t)tinfo;

	// get threads in the task
	kr = task_threads(port, &thread_list, &thread_count);
	if (kr != KERN_SUCCESS)
	{
		printf("task_threads() returned %d, terminating.\n", kr);
		return -3;
	}
	if (thread_count > 0)
	{
		stat_thread += thread_count;
	}

	long tot_sec = 0;
	long tot_usec = 0;
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
			tot_sec = tot_sec + basic_info_th->user_time.seconds + basic_info_th->system_time.seconds;
			tot_usec = tot_usec + basic_info_th->system_time.microseconds + basic_info_th->system_time.microseconds;
			tot_cpu = tot_cpu + basic_info_th->cpu_usage;
			printf("Thread %d: CPU %d%%\n", thread_list[j], basic_info_th->cpu_usage);
		}
	}
	printf("---\nTotal: CPU %ld%%\n", tot_cpu);
	return 0;
}
