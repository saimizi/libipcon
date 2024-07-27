if(UNIT_TEST)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DUNIT_TEST")
endif()

set(JSLIST_SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/jsutils/jslist/jslist.c)
add_library(jslist STATIC ${JSLIST_SOURCE})

set(JSLIST_INCLUDE ${CMAKE_CURRENT_SOURCE_DIR}/jsutils/jslist)

set(SAMPLE_COMMON_CFLAGS
    "-g \
    -O2 \
	-funwind-tables")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${SAMPLE_COMMON_CFLAGS}")
set(SAMPLE_COMMON_INCLUDE
    "${PROJECT_SOURCE_DIR}/driver" "${PROJECT_SOURCE_DIR}/lib"
    "${PROJECT_SOURCE_DIR}/logger" "${JSLIST_INCLUDE}")

add_executable(ipcon_server "ipcon_server.c")
target_link_libraries(ipcon_server ipcon ${LIBNL_GENL_LIBRARIES} jslist)
target_include_directories(ipcon_server PUBLIC ${SAMPLE_COMMON_INCLUDE})

add_executable(ipcon_server_poll "ipcon_server_poll.c")
target_link_libraries(ipcon_server_poll ipcon ${LIBNL_GENL_LIBRARIES} jslist)
target_include_directories(ipcon_server_poll PUBLIC ${SAMPLE_COMMON_INCLUDE})

add_executable(ipcon_sender "ipcon_sender.c")
target_link_libraries(ipcon_sender ipcon ${LIBNL_GENL_LIBRARIES} jslist)
target_include_directories(ipcon_sender PUBLIC ${SAMPLE_COMMON_INCLUDE})

add_executable(ipcon_user "ipcon_user.c")
target_link_libraries(ipcon_user ipcon ${LIBNL_GENL_LIBRARIES} jslist)
target_include_directories(ipcon_user PUBLIC ${SAMPLE_COMMON_INCLUDE})
