cmake_minimum_required(VERSION 3.10)

project(libipcon VERSION 0.1.0)

# Enable cmake makefile debug
set(CMAKE_VERBOSE_MAKEFILE ON)

include(GNUInstallDirs)

include(FindPkgConfig)
pkg_check_modules(LIBNL_GENL REQUIRED libnl-genl-3.0)
message("FOUND: ${LIBNL_GENL_FOUND}")
message("MODULE_NAME: ${LIBNL_GENL_MODULE_NAME}")
message("LIBRARY: ${LIBNL_GENL_LIBRARIES}")
message("LINK_LIBRARY: ${LIBNL_GENL_LIBRARIES}")
message("LIBRARY_DIRS: ${LIBNL_GENL_DIRS}")
message("LDFLAGS: ${LIBNL_GENL_LDFLAGS}")
message("LDFLAGS_OTHER: ${LIBNL_GENL_LDFLAGS_OTHER}")
message("INCLUDE_DIRS: ${LIBNL_GENL_INCLUDE_DIRS}")
message("CFLAGS: ${LIBNL_GENL_CFLAGS}")
message("CFLAGS_OTHER: ${LIBNL_GENL_CFLAGS_OTHER}")

add_subdirectory(lib)

if(UNIT_TEST)
  add_subdirectory(test)
  if(BUILD_LOGGER)
    message(WARNING "BUILD_LOGGER is ignored when UNIT_TEST is enabled")
  endif()

  if(BUILD_SAMPLES)
    message(WARNING "BUILD_SAMPLES is ignored when UNIT_TEST is enabled")
  endif()
else()
  if(BUILD_LOGGER)
    add_subdirectory(logger)
  endif()
  if(BUILD_SAMPLES)
    add_subdirectory(samples)
  endif()
endif()
