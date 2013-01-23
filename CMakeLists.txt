CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

PROJECT(yamdns)

ADD_DEFINITIONS(-pedantic -std=gnu99 -Wall -Werror)

INCLUDE_DIRECTORIES(include)

ADD_EXECUTABLE(yamdns
include/dump.h
include/mdns.h
src/main.c
src/dump.c
src/mdns.c
)
