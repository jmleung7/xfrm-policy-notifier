cmake_minimum_required(VERSION 3.18)

project(xfrm_policy_notifier C)

find_library(NL_LIBRARY NAMES nl nl-3 REQUIRED)
find_library(NL_XFRM_LIBRARY NAMES nl-xfrm nl-xfrm-3 REQUIRED)
set(NL_LIBRARIES ${NL_LIBRARY} ${NL_XFRM_LIBRARY})
find_path(NL_INCLUDE_DIRS netlink/version.h PATH_SUFFIXES libnl3 REQUIRED)

add_executable(xfrm_policy_notifier src/main.c)

target_link_libraries(xfrm_policy_notifier ${NL_LIBRARIES})
target_include_directories(xfrm_policy_notifier PRIVATE ${NL_INCLUDE_DIRS})
