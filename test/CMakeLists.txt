# ####################### mock_lib ############################
# Build mock_lib and export wrap_symbols
set(MOCK_LIB_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/mock_lib/libc_mock.c)

add_library(mock_lib SHARED ${MOCK_LIB_SOURCES})
target_include_directories(mock_lib PUBLIC ${PROJECT_SOURCE_DIR}/lib
                                           ${PROJECT_SOURCE_DIR}/driver)
target_link_libraries(mock_lib cmocka)

# Reconfigure to set WRAP_SYMBOLES if mock library sources are changed.
set_property(
  DIRECTORY
  APPEND
  PROPERTY CMAKE_CONFIGURE_DEPENDS ${MOCK_LIB_SOURCES})

execute_process(COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/scripts/get_mocks.sh
                        ${MOCK_LIB_SOURCES} OUTPUT_VARIABLE WRAP_SYMBOLES)

# Create interface library for linking mock_lib
add_library(wrap_symbols INTERFACE)
target_link_libraries(wrap_symbols INTERFACE mock_lib)
target_link_options(wrap_symbols INTERFACE "-Wl,${WRAP_SYMBOLES}")

# ############# libipcon_mock_lib ############################
add_library(libipcon_mock_lib SHARED
            ${CMAKE_CURRENT_SOURCE_DIR}/libipcon_mock_lib/libipcon_mock.c)
target_include_directories(
  libipcon_mock_lib
  PUBLIC ${PROJECT_SOURCE_DIR}/lib ${PROJECT_SOURCE_DIR}/driver
         ${LIBNL_GENL_INCLUDE_DIRS})

# Reconfigure to set WRAP_SYMBOLES if mock library sources are changed.
set_property(
  DIRECTORY
  APPEND
  PROPERTY CMAKE_CONFIGURE_DEPENDS
           ${CMAKE_CURRENT_SOURCE_DIR}/libipcon_mock_lib/libipcon_mock.c)

execute_process(
  COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/scripts/get_mocks.sh
          ${CMAKE_CURRENT_SOURCE_DIR}/libipcon_mock_lib/libipcon_mock.c
  OUTPUT_VARIABLE LIBIPCON_WRAP_SYMBOLES)

add_library(libipcon_wrap_symbols INTERFACE)
target_link_libraries(wrap_symbols INTERFACE libipcon_mock_lib)
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
