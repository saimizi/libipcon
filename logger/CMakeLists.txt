if(UNIT_TEST)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DUNIT_TEST")
endif()

set(LOGGER_COMMON_CFLAGS
    "-g \
    -O2 \
	-Wall")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${LOGGER_COMMON_CFLAGS}")

set(LOGGER_COMMON_INCLUDE "${PROJECT_SOURCE_DIR}/driver"
                          "${PROJECT_SOURCE_DIR}/lib")

add_executable(ipcon_cmd "ipcon_cmd.c")
target_link_libraries(ipcon_cmd ipcon ${LIBNL_GENL_LIBRARIES})
target_include_directories(ipcon_cmd PUBLIC ${LOGGER_COMMON_INCLUDE})

add_executable(ipcon_logger "ipcon_logger.c")
target_link_libraries(ipcon_logger ipcon ${LIBNL_GENL_LIBRARIES})
target_include_directories(ipcon_logger PUBLIC ${LOGGER_COMMON_INCLUDE})

add_executable(ipcon_kevent "ipcon_kevent.c")
target_link_libraries(ipcon_kevent ipcon ${LIBNL_GENL_LIBRARIES})
target_include_directories(ipcon_kevent PUBLIC ${LOGGER_COMMON_INCLUDE})
