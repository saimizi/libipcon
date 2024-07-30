add_subdirectory(mocklib)

# ############# libipcon_mocklib ############################
add_library(ipcon_mocklib SHARED
            ${CMAKE_CURRENT_SOURCE_DIR}/libipcon_mocklib/libipcon_mock.c)
target_include_directories(
  ipcon_mocklib
  PUBLIC ${PROJECT_SOURCE_DIR}/lib ${PROJECT_SOURCE_DIR}/driver
         ${LIBNL_GENL_INCLUDE_DIRS})

# Reconfigure to set WRAP_SYMBOLES if mock library sources are changed.
set_property(
  DIRECTORY
  APPEND
  PROPERTY CMAKE_CONFIGURE_DEPENDS
           ${CMAKE_CURRENT_SOURCE_DIR}/libipcon_mocklib/libipcon_mock.c)

execute_process(
  COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/mocklib/scripts/get_mocks.sh
          ${CMAKE_CURRENT_SOURCE_DIR}/libipcon_mocklib/libipcon_mock.c
  OUTPUT_VARIABLE LIBIPCON_WRAP_SYMBOLES)

add_library(libipcon_wrap_symbols INTERFACE)
target_link_libraries(libipcon_wrap_symbols INTERFACE ipcon_mocklib)
target_link_options(libipcon_wrap_symbols INTERFACE
                    "-Wl,${LIBIPCON_WRAP_SYMBOLES}")

# Sample test program
add_executable(sample01 sample.c)
target_link_libraries(sample01 cmocka wrap_symbols)

set(LIBIPCON_INCLUDE ${PROJECT_SOURCE_DIR}/lib/ LIBNL_GENL_INCLUDE_DIRS)

# ######################### libipcon ############################
add_executable(ut_ipcon_create_handler ut_ipcon_create_handler.c)
target_link_libraries(ut_ipcon_create_handler cmocka wrap_symbols ipcon
                      libipcon_wrap_symbols)
target_include_directories(ut_ipcon_create_handler PUBLIC ${LIBIPCON_INCLUDE})
