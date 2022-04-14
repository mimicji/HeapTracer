cmake_minimum_required(VERSION 3.5.1)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(OPT_CFLAGS "-O3 -g")
find_package(DynamoRIO)
if (NOT DynamoRIO_FOUND)
  message(FATAL_ERROR "DynamoRIO package required to build")
endif(NOT DynamoRIO_FOUND)
option(OPTIMIZE_SAMPLES
  "Build samples with optimizations to increase the chances of clean call inlining (overrides debug flags)"
  ON)
add_library(heaptracer SHARED "heaptracer.cpp;")
target_include_directories(heaptracer PUBLIC)

configure_DynamoRIO_client(heaptracer)
use_DynamoRIO_extension(heaptracer drmgr)
use_DynamoRIO_extension(heaptracer drutil)
use_DynamoRIO_extension(heaptracer drreg)
use_DynamoRIO_extension(heaptracer drx)
use_DynamoRIO_extension(heaptracer droption) 
use_DynamoRIO_extension(heaptracer drsyms) 
use_DynamoRIO_extension(heaptracer drcallstack) 
use_DynamoRIO_extension(heaptracer drwrap) 

