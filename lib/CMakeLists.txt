if(UNIT_TEST)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DUNIT_TEST")
endif()

set(LIBIPCON_CFLAGS
    "-g \
    -Wextra \
    -Werror \
    -Wformat=2 \
    -Wcast-qual \
    -Wcast-align \
    -Wconversion \
    -Wfloat-equal \
    -Wpointer-arith \
    -Wswitch-enum \
    -Wno-unused-function \
    -O2 \
    -U_FORTIFY_SOURCE \
    -D_FORTIFY_SOURCE=2 \
    -ftrapv \
    -fstack-protector \
    -rdynamic \
    -funwind-tables")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${LIBIPCON_CFLAGS}")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} \
	-Wl,--version-script,${CMAKE_CURRENT_SOURCE_DIR}/ipcon.map")

set(LIBIPCON_INCLUDE_DIR
    ${CMAKE_CURRENT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/driver
    ${LIBNL_GENL_INCLUDE_DIRS})

# Build libipcon
set(LIBIPCON_SOURCE_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/libipcon.c ${CMAKE_CURRENT_SOURCE_DIR}/util.c
    ${CMAKE_CURRENT_SOURCE_DIR}/libipcon_dbg.c
    ${CMAKE_CURRENT_SOURCE_DIR}/libipcon_priv.c)

add_library(ipcon SHARED ${LIBIPCON_SOURCE_FILES})
target_link_libraries(ipcon ${LIBNL_GENL_LIBRARIES})
set_target_properties(ipcon PROPERTIES VERSION ${CMAKE_PROJECT_VERSION}
                                       SOVERSION ${PROJECT_VERSION_MAJOR})
target_include_directories(ipcon PUBLIC ${LIBIPCON_INCLUDE_DIR})
