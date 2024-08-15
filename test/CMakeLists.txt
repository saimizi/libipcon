add_subdirectory(mocklib)

set(LIBIPCON_INCLUDE ${PROJECT_SOURCE_DIR}/lib/ LIBNL_GENL_INCLUDE_DIRS)

# ######################### libipcon ############################
set(UT_SOURCES ut_main.c ut_ipcon_create_handler.c)
add_executable(ut_ipcon ${UT_SOURCES})
target_link_libraries(ut_ipcon cmocka wrap_symbols ipcon)
target_include_directories(ut_ipcon PUBLIC ${LIBIPCON_INCLUDE})
