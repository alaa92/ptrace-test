#include <iostream>
#include <thread>
#include <chrono>
#include <unistd.h>
#include <dlfcn.h>

extern "C" void* __libc_dlopen_mode(const char *__file, int __mode);

int main()
{
    std::cout << "PID: " << getpid() << std::endl;
    std::cout << "dlopen: " << (void*)__libc_dlopen_mode << std::endl;
    while(1)
    {
        std::cout << "Waiting..." << std::endl;
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }
    return 0;
}