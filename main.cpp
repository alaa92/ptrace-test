#include <iostream>
#include <cstring>
#include <sstream>
#include <istream>
#include <fstream>
#include <dirent.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <sys/io.h>
#include <sys/uio.h>
#include <dlfcn.h>
#include <link.h>
#include <fcntl.h>

#if defined(_M_IX86) || defined(__i386__) || __WORDSIZE == 32
#define ARCH_86 /* The code is being compiled for 32 bits */
#elif defined(_M_X64) || defined(__LP64__) || defined(_LP64) || __WORDSIZE == 64
#define ARCH_64 /* The code is being compiled for 64 bits */
#endif

/* Helper macros */
#if defined(ARCH_86)
#define strtoptr(nptr, endptr, base) strtoul(nptr, endptr, base)
#elif defined(ARCH_64)
#define strtoptr(nptr, endptr, base) strtoull(nptr, endptr, base)
#endif

pid_t get_process_id(std::string process_name)
{
    pid_t pid = (pid_t)-1;
    DIR* pdir = opendir("/proc"); //Open directory stream
	if (!pdir)
		return pid;

    if(process_name.back() != '\0') process_name += '\0'; //Making sure the null terminator is there

	struct dirent* pdirent; //Directory structure entry
	while (pid == -1 && (pdirent = readdir(pdir)))
	{
		pid_t id = (pid_t)atoi(pdirent->d_name);
		if (id > 0)
		{
            std::stringstream cmd_line_path;
            cmd_line_path << "/proc/";
            cmd_line_path << id;
            cmd_line_path << "/cmdline";

            /* cmd_line_path's string now should be: /proc/<id>/cmdline
             * we're going to use it to read the cmdline file's content through
             * a file stream.
             */

            //std::cout << "Command Line Path: " << cmd_line_path.str() << std::endl;

            std::ifstream cmd_line_fs(cmd_line_path.str(), std::ios::binary); //Open file stream of /proc/<id>/cmdline
            if(!cmd_line_fs.is_open()) continue;

            //Store the content of the cmdline file into 'cmd_line'
            std::stringstream cmd_line;
            cmd_line << cmd_line_fs.rdbuf();
            /* Now, let's parse the cmd_line string to get the process name */

            //std::cout << "Command Line: " << cmd_line.str() << std::endl;

            size_t proc_name_pos = cmd_line.str().rfind('/') + 1; /*Find the position of the last '/', 
                                                                        as it will be followed by the process name */

			std::string cur_process_name = cmd_line.str().substr(proc_name_pos); /* Get a substring of the cmd_line that 
                                                                                        goes from the slash position to the end of the string */

            if(cur_process_name.back() != '\0') cur_process_name += '\0'; //Making sure the null terminator is there

            cmd_line_fs.close(); //Close file stream

            //std::cout << "Current Process Name: " << cur_process_name << std::endl;

			if (!strcmp(process_name.c_str(), cur_process_name.c_str())) //Compare the current process name with the one we want
            {
                pid = id;
                //std::cout << "Process ID found: " << pid << std::endl;
                break;
            }

            //std::cout << "--------------------" << std::endl;
		}
	}

	closedir(pdir); //Close directory stream

    return pid;
}

void read_memory(pid_t pid, void* src, void* dst, size_t size)
{
    /*
    pid  = target process id
    src  = address to read from on the target process
    dst  = address to write to on the caller process
    size = size of the buffer that will be read
    */

    struct iovec iosrc;
	struct iovec iodst;
	iodst.iov_base = dst;
	iodst.iov_len  = size;
	iosrc.iov_base = src;
	iosrc.iov_len  = size;

    process_vm_readv(pid, &iodst, 1, &iosrc, 1, 0);
}

void write_memory(pid_t pid, void* dst, void* src, size_t size)
{
    /*
    pid  = target process id
    dst  = address to write to on the target process
    src  = address to read from on the caller process
    size = size of the buffer that will be read
    */

    struct iovec iosrc;
	struct iovec iodst;
	iosrc.iov_base = src;
	iosrc.iov_len  = size;
	iodst.iov_base = dst;
	iodst.iov_len  = size;

    process_vm_writev(pid, &iosrc, 1, &iodst, 1, 0);
}

void* inject_syscall(
    pid_t pid, 
    int syscall_n, 
    void* arg0, 
    void* arg1, 
    void* arg2, 
    void* arg3, 
    void* arg4, 
    void* arg5
){
    void* ret = (void*)-1;
    int status;
    struct user_regs_struct old_regs, regs;
    void* injection_addr = (void*)-1;

    //This buffer is our payload, which will run a syscall properly on x86/x64
    unsigned char injection_buf[] =
    {
#       if defined(ARCH_86) //32 bits syscall
        0xcd, 0x80, //int80 (syscall)
#       elif defined(ARCH_64) //64 bits syscall
        0x0f, 0x05, //syscall
#       endif
        /* these nops are here because
         * we're going to write memory using
         * ptrace, and it always writes the size
         * of a word, which means we have to make
         * sure the buffer is long enough
        */
		0x90, //nop
		0x90, //nop
		0x90, //nop
		0x90, //nop
		0x90, //nop
		0x90  //nop
    };

    //As ptrace will always write a uintptr_t, let's make sure we're using proper buffers
    uintptr_t old_data;
    uintptr_t injection_buffer;
    memcpy(&injection_buffer, injection_buf, sizeof(injection_buffer));

    //Attach to process using 'PTRACE_ATTACH'
    ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    wait(&status);

    /* Get the current registers using 'PTRACE_GETREGS' so that
     * we can restore the execution later
     * and also modify the bytes of EIP/RIP
    */

    ptrace(PTRACE_GETREGS, pid, NULL, &old_regs);
    regs = old_regs;

    //Now, let's set up the registers that will be injected into the tracee

#   if defined(ARCH_86)
    regs.eax = (uintptr_t)syscall_n;
    regs.ebx = (uintptr_t)arg0;
    regs.ecx = (uintptr_t)arg1;
    regs.edx = (uintptr_t)arg2;
    regs.esi = (uintptr_t)arg3;
    regs.edi = (uintptr_t)arg4;
    regs.ebp = (uintptr_t)arg5;
    injection_addr = (void*)regs.eip;
#   elif defined(ARCH_64)
    regs.rax = (uintptr_t)syscall_n;
    regs.rdi = (uintptr_t)arg0;
    regs.rsi = (uintptr_t)arg1;
    regs.rdx = (uintptr_t)arg2;
    regs.r10 = (uintptr_t)arg3;
    regs.r8  = (uintptr_t)arg4;
    regs.r9  = (uintptr_t)arg5;
    injection_addr = (void*)regs.rip;
#   endif

    //Let's store the buffer at EIP/RIP that we're going to modify into 'old_data' using 'PTRACE_PEEKDATA'
    old_data = (uintptr_t)ptrace(PTRACE_PEEKDATA, pid, injection_addr, NULL);

    //Let's write our payload into the EIP/RIP of the target process using 'PTRACE_POKEDATA'
    ptrace(PTRACE_POKEDATA, pid, injection_addr, injection_buffer);

    //Let's inject our modified registers into the target process using 'PTRACE_SETREGS'
    ptrace(PTRACE_SETREGS, pid, NULL, &regs);

    //Let's run a single step in the target process (execute one assembly instruction)
    ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
    waitpid(pid, &status, WSTOPPED); //Wait for the instruction to run

    //Let's get the registers after the syscall to store the return value
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
#   if defined(ARCH_86)
    ret = (void*)regs.eax;
#   elif defined(ARCH_64)
    ret = (void*)regs.rax;
#   endif

    //Let's write the old data at EIP/RIP
    ptrace(PTRACE_POKEDATA, pid, (void*)injection_addr, old_data);

    //Let's restore the old registers to continue the normal execution
    ptrace(PTRACE_SETREGS, pid, NULL, &old_regs);
    ptrace(PTRACE_DETACH, pid, NULL, NULL); //Detach and continue the execution

    return ret;
}

void* allocate_memory(pid_t pid, size_t size, int protection)
{
    //mmap template:
    //void *mmap (void *__addr, size_t __len, int __prot, int __flags, int __fd, __off_t __offset);

    void* ret = (void*)-1;
#   if defined(ARCH_86)
    ret = inject_syscall(
        pid, 
        //__NR_mmap has been deprecated for 32 bits a long time ago, so we're going to use __NR_mmap2
        __NR_mmap2, //syscall number
        //arguments
        (void*)0, 
        (void*)size, 
        (void*)protection, 
        (void*)(MAP_ANON | MAP_PRIVATE), 
        (void*)-1, 
        (void*)0
    );
#   elif defined(ARCH_64)
    ret = inject_syscall(
        pid, 
        __NR_mmap, //syscall number
        //arguments
        (void*)0, 
        (void*)size, 
        (void*)(uintptr_t)protection, 
        (void*)(MAP_ANON | MAP_PRIVATE), 
        (void*)-1, 
        (void*)0
    );
#   endif

    return ret;
}

void deallocate_memory(pid_t pid, void* src, size_t size)
{
    //munmap template
    //int munmap (void *__addr, size_t __len);
    inject_syscall(pid, __NR_munmap, src, (void*)size, NULL, NULL, NULL, NULL);
}

void* protect_memory(pid_t pid, void* src, size_t size, int protection)
{
    //mprotect template
    //int mprotect (void *__addr, size_t __len, int __prot);
    return inject_syscall(pid, __NR_mprotect, src, (void*)size, (void*)(uintptr_t)protection, NULL, NULL, NULL);
}

void test_ptrace(pid_t pid)
{
    int status;
    struct user_regs_struct regs;
    unsigned char inj_buf[] =
    {
        0xCD, 0x80,               //int80 (syscall)
        0xCC,                     //int3  (SIGTRAP)
    };

    void* inj_addr = allocate_memory(pid, sizeof(inj_buf), PROT_EXEC | PROT_READ | PROT_WRITE);
    write_memory(pid, inj_addr, inj_buf, sizeof(inj_buf));

    std::cout << "--ptrace test started--" << std::endl;

    if(ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1)
    {
        perror("PTRACE_ATTACH");
        std::cout << "Errno: " << errno << std::endl;
        return;
    }

    wait(&status);

    if(ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1)
    {
        perror("PTRACE_GETREGS");
        std::cout << "Errno: " << errno << std::endl;
        return;
    }

    regs.eax = __NR_exit;
    regs.ebx = 222;
    regs.eip = (unsigned long)inj_addr;

    if(ptrace(PTRACE_SETREGS, pid, NULL, &regs) == -1)
    {
        perror("PTRACE_SETREGS");
        std::cout << "Errno: " << errno << std::endl;
        return;
    }

    if(ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1)
    {
        perror("PTRACE_DETACH");
        std::cout << "Errno: " << errno << std::endl;
        return;
    }

    std::cout << "--ptrace test ended--" << std::endl;
}

void* load_library(pid_t pid, std::string path, int mode)
{
    int status;
    struct user_regs_struct old_regs, regs;
    void* dlopen_ex = (void*)0xf7c29700;
    void* handle_ex = (void*)-1;

    unsigned char inj_buf[] =
    {
        0x51,       //push ecx
        0x53,       //push ebx
        0xFF, 0xD0, //call eax
        0xCC,       //int3 (SIGTRAP)
    };

    size_t path_size = path.size();
    size_t inj_size  = sizeof(inj_buf) + path_size;
    void*  inj_addr  = allocate_memory(pid, inj_size, PROT_EXEC | PROT_READ | PROT_WRITE);
    void*  path_addr = (void*)((uintptr_t)inj_addr + sizeof(inj_buf));
    write_memory(pid, inj_addr, (void*)inj_buf, sizeof(inj_buf));
    write_memory(pid, path_addr, (void*)path.c_str(), path_size);

    ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    wait(&status);
    ptrace(PTRACE_GETREGS, pid, NULL, &old_regs);

    regs.eax = (unsigned long)dlopen_ex;
    regs.ebx = (unsigned long)path_addr;
    regs.ecx = (unsigned long)mode;
    regs.eip = (unsigned long)inj_addr;

    if(ptrace(PTRACE_SETREGS, pid, NULL, &regs) == -1)
    {
        perror("PTRACE_ATTACH");
        std::cout << "Errno: " << errno << std::endl;
        return handle_ex;
    }
    
    if(ptrace(PTRACE_CONT, pid, NULL, NULL) == -1)
    {
        perror("PTRACE_CONT");
        std::cout << "Errno: " << errno << std::endl;
        return handle_ex;
    }

    waitpid(pid, &status, WSTOPPED);
    if(ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1)
    {
        perror("PTRACE_GETREGS");
        std::cout << "Errno: " << errno << std::endl;
        return handle_ex;
    }

    handle_ex = (void*)old_regs.eax;

    if(ptrace(PTRACE_SETREGS, pid, NULL, &old_regs) == -1)
    {
        perror("PTRACE_SETREGS");
        std::cout << "Errno: " << errno << std::endl;
        return handle_ex;
    }

    if(ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1)
    {
        perror("PTRACE_DETACH");
        std::cout << "Errno: " << errno << std::endl;
        return handle_ex;
    }

    deallocate_memory(pid, inj_addr, inj_size);

    return handle_ex;
}

int main()
{
    pid_t pid = get_process_id("target");
    std::cout << "PID: " << pid << std::endl;
    std::string lib_path = "/home/rdbo/Documents/Codes/C/ptrace-test/libtest.so";
    load_library(pid, lib_path, RTLD_LAZY);
    return 0;
}