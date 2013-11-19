CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

PROJECT(yamdns)

ADD_DEFINITIONS(-pedantic -std=gnu99 -Wall -Werror)

INCLUDE_DIRECTORIES(include)

ADD_EXECUTABLE(yamdns
include/yamdns/yamdns.h
include/yamdns/type.h
include/dump.h
src/main.c
src/dump.c
src/yamdns.c
src/network.c
)
