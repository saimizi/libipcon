if(UNIT_TEST)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DUNIT_TEST")

  # --wrap may fails when using O2/Os
  set(LIBIPCON_CFLAGS "-g -O1")
  add_definitions(-Dmalloc=_test_malloc -Dfree=_test_free -Dcalloc=test_calloc
                  -Drealloc=test_realloc)

  if(ENABLE_COVERAGE)
    if(CMAKE_COMPILER_IS_GNUCC)
      set(LIBIPCON_CFLAGS "${LIBIPCON_CFLAGS} -fprofile-arcs -ftest-coverage")
    endif()
  endif()

else()
  set(LIBIPCON_CFLAGS "-g -O2")
endif()

set(LIBIPCON_CFLAGS
    "${LIBIPCON_CFLAGS} \
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

if(UNIT_TEST)
  add_library(ipcon STATIC ${LIBIPCON_SOURCE_FILES})
  if(ENABLE_COVERAGE)
    if(CMAKE_COMPILER_IS_GNUCC)
      target_link_libraries(ipcon "-lgcov --coverage")
    endif()
  endif()
else()
  add_library(ipcon SHARED ${LIBIPCON_SOURCE_FILES})
endif()
target_link_libraries(ipcon ${LIBNL_GENL_LIBRARIES})

set_target_properties(ipcon PROPERTIES VERSION ${CMAKE_PROJECT_VERSION}
                                       SOVERSION ${PROJECT_VERSION_MAJOR})
target_include_directories(ipcon PUBLIC ${LIBIPCON_INCLUDE_DIR})
