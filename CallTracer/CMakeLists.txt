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
add_library(calltracer SHARED "calltracer.cpp;")
target_include_directories(calltracer PUBLIC)

configure_DynamoRIO_client(calltracer)
use_DynamoRIO_extension(calltracer drmgr)
use_DynamoRIO_extension(calltracer drutil)
use_DynamoRIO_extension(calltracer drreg)
use_DynamoRIO_extension(calltracer drx)
use_DynamoRIO_extension(calltracer droption) 
use_DynamoRIO_extension(calltracer droption) 
use_DynamoRIO_extension(calltracer drsyms) 

