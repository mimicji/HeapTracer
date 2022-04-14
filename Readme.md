# HeapTracer
A simple tracer that records function calls and heap operations.
## Dependencies
- DynamoRIO >= 9.0.0
- libunwind-dev
## Usage
On Linux:
- Build: ./build.sh
- Run: ./heaptracer.sh \<application\>
  
On Windows:
- Build&Run: Currently no auto script supported. Please check [DynamoRIO Document](https://dynamorio.org/page_build_client.html).

## Where is your trace
HeapTrace tells you during execution.
```
kaihang@laptop:~/project/HeapTracer$ ./heaptracer.sh ls
[HeapTracer] Start tracing.
[HeapTracer] Trace file /home/kaihang/project/HeapTracer/build/calltrace.ls.22457.0000.log created
[HeapTracer] Trace file /home/kaihang/project/HeapTracer/build/heaptrace.ls.22457.0000.log created
build	    CMakeLists.txt  heaptracer.hpp	     Readme.md
build.sh  heaptracer.cpp  heaptracer.sh   
```
## Trace files
There are two trace files, calltrace and heaptrace.

Calltrace contains all function calls and returns during execution.

Heaptrace contains the call stacks, arguments, and return value of alloc and free invokations.  

## Examples
Heaptrace:
```
========================================================
0:   __GI___libc_malloc@libc.so.6
1:   main@malloc_test
2:   __libc_start_main@libc.so.6
3:   0x00007f08983665aa@malloc_test
[22] malloc(0x400) = 0x00007f0898569260
========================================================
0:   __GI___libc_malloc@libc.so.6
1:   main@malloc_test
2:   __libc_start_main@libc.so.6
3:   0x00007f08983665aa@malloc_test
[23] malloc(0x800) = 0x00007f0898569670
========================================================
0:   __GI___libc_free@libc.so.6
1:   main@malloc_test
2:   __libc_start_main@libc.so.6
3:   0x00007f08983665aa@malloc_test
[3] free(0x7f0898569260)
========================================================
0:   __GI___libc_free@libc.so.6
1:   main@malloc_test
2:   __libc_start_main@libc.so.6
3:   0x00007f08983665aa@malloc_test
[4] free(0x7f0898569670)
```
  
Calltrace:
```
CALL @  0x00007f089c33d093 ld-linux-x86-64.so.2!_start+0x3 /build/glibc-uZu3wS/glibc-2.27/elf/rtld.c:746+0x32
  to  0x00007f089c33dea0 ld-linux-x86-64.so.2!_dl_start+0x0 /build/glibc-uZu3wS/glibc-2.27/elf/rtld.c:444+0x0
  RSP=0x00007ffddf733ee0
  CALL @  0x00007f089c33e0c3 ld-linux-x86-64.so.2!_dl_start+0x223 /build/glibc-uZu3wS/glibc-2.27/elf/rtld.c:393+0x0
    to  0x00007f089c348100 ld-linux-x86-64.so.2!_dl_setup_hash+0x0 /build/glibc-uZu3wS/glibc-2.27/elf/dl-lookup.c:939+0x0
    RSP=0x00007ffddf733e60
  RETURN @  0x00007f089c34815d ld-linux-x86-64.so.2!_dl_setup_hash+0x5d /build/glibc-uZu3wS/glibc-2.27/elf/dl-lookup.c:961+0x0
    TO  0x00007f089c33e0c8 ld-linux-x86-64.so.2!_dl_start+0x228 /build/glibc-uZu3wS/glibc-2.27/elf/rtld.c:394+0x0
    RSP=0x00007ffddf733e58
  CALL @  0x00007f089c33e123 ld-linux-x86-64.so.2!_dl_start+0x283 /build/glibc-uZu3wS/glibc-2.27/elf/rtld.c:414+0x0
    to  0x00007f089c356a60 ld-linux-x86-64.so.2!_dl_sysdep_start+0x0 ../elf/dl-sysdep.c:88+0x0
    RSP=0x00007ffddf733e60
    CALL @  0x00007f089c356de5 ld-linux-x86-64.so.2!_dl_sysdep_start+0x385 ../elf/dl-sysdep.c:224+0x0
      to  0x00007f089c354dd0 ld-linux-x86-64.so.2!__GI___tunables_init+0x0 /build/glibc-uZu3wS/glibc-2.27/elf/dl-tunables.c:289+0x0
      RSP=0x00007ffddf733dd0
```
