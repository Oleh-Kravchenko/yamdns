CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

PROJECT(yamdns)

ADD_DEFINITIONS(-pedantic -std=gnu99 -Wall -Werror)

INCLUDE_DIRECTORIES(include)

ADD_EXECUTABLE(yamdns
include/mdns/type.h
include/mdns/mdns.h
include/dump.h
src/main.c
src/dump.c
src/mdns.c
src/network.c
)
