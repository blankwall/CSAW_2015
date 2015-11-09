#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <mach/mach_types.h>
#include <mach/mach_traps.h>
#include <limits.h>
#include <mach/boolean.h>
#include <mach/error.h>
#include <mach/mach_error.h>
#include <unistd.h> 
#include <sys/ptrace.h> 
#include <mach/mach.h> 
#include <errno.h> 
#include <err.h>
#include <mach/mach_vm.h>

vm_address_t get_base_address(mach_port_t task){
	kern_return_t kret;
	vm_region_basic_info_data_t info;
	vm_size_t size;
	mach_port_t object_name;
	mach_msg_type_number_t count;
	vm_address_t firstRegionBegin;
	mach_vm_address_t address = 1;

	count = VM_REGION_BASIC_INFO_COUNT_64;
	kret = mach_vm_region(task, &address, (mach_vm_size_t *) &size, VM_REGION_BASIC_INFO, (vm_region_info_t) &info, &count, &object_name);


	return address;
}

int main(int argc, char** argv){
	mach_port_t task;
	int infoPid;

	if(argc < 2){
		printf("USAGE [pid]\n");
		exit(-1);
	}


	infoPid = atoi(argv[1]);

	task_for_pid(current_task(), infoPid, &task);

	printf("Base Address: 0x%lx\n", get_base_address(task));
}