add_subdirectory(mocklib)

if(ENABLE_COVERAGE)
  if(CMAKE_COMPILER_IS_GNUCC OR CMAKE_C_COMPILER_ID MATCHES "Clang")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fprofile-arcs -ftest-coverage")
  endif()
endif()

set(LIBIPCON_INCLUDE ${PROJECT_SOURCE_DIR}/lib/ LIBNL_GENL_INCLUDE_DIRS)

# ######################### libipcon ############################
set(UT_SOURCES ut_main.c ut_ipcon_create_handler.c)
add_executable(ut_ipcon ${UT_SOURCES})
target_link_libraries(ut_ipcon cmocka wrap_symbols ipcon)
target_include_directories(ut_ipcon PUBLIC ${LIBIPCON_INCLUDE})

if(ENABLE_COVERAGE)
  if(CMAKE_COMPILER_IS_GNUCC OR CMAKE_C_COMPILER_ID MATCHES "Clang")
    target_link_libraries(ut_ipcon "--coverage")
  endif()
endif()
