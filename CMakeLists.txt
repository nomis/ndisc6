project (NDISC6 C)
site_name (SITE)
set (PACKAGE ndisc6 CACHE STRING "Name of the project")
set (VERSION 0.9.1 CACHE STRING "Version of the project")

set (CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)

add_definitions (-DHAVE_CONFIG_H)
add_definitions (-std=gnu99)

set (CMAKE_C_FLAGS "-Wall -Wextra ${CMAKE_C_FLAGS}")
add_definitions (-D_FORTIFY_SOURCE=2)

# Checks for programs.
include (FindPerl)

# Checks for libraries.
include (CheckLibraryExists)

check_library_exists (rt clock_gettime "" HAVE_LIBRT)
check_library_exists (rt clock_nanosleep "" HAVE_CLOCK_NANOSLEEP)
if (HAVE_LIBRT)
	set (LIBRT "-lrt")
endif (HAVE_LIBRT)

include (FindGettext)
if (GETTEXT_FOUND)
	set (ENABLE_NLS 1)
endif (GETTEXT_FOUND)

# Check for headers
include (CheckIncludeFile)
check_include_file ("getopt.h" HAVE_GETOPT_H)

# Check for functions
include (CheckFunctionExists)
check_function_exists (inet6_rth_add HAVE_INET6_RTH_ADD)

# Targets
configure_file (config.cmake config.h)
add_subdirectory (src)

