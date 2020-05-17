project(libagamotto)

file(GLOB agamotto_SRC
  "src/*.c"
)

add_library(agamotto
  SHARED
  ${agamotto_SRC}
)

add_library(agamotto_nomain
  SHARED
  $<TARGET_OBJECTS:libafl>
)

target_link_libraries(agamotto_nomain PUBLIC dl)

set(COMMON_FLAGS "-D_GNU_SOURCE")
set(COMMON_FLAGS "${COMMON_FLAGS} -Wall -fPIC -fno-strict-aliasing")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${COMMON_FLAGS}")

target_link_libraries(agamotto PUBLIC ${CMAKE_DL_LIBS} pthread)

message(STATUS ${CMAKE_CURRENT_SOURCE_DIR})

set(LIBAFL_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../libafl)

target_include_directories(agamotto PUBLIC ${LIBAFL_PATH}/src)
target_include_directories(agamotto PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(agamotto PUBLIC afl)

add_custom_command(
  TARGET agamotto_nomain POST_BUILD
  COMMAND cp ${LIBAFL_PATH}/src/libafl.h libafl.h
)
