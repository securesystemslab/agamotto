project(libafl)

add_library(afl
  STATIC
  $<TARGET_OBJECTS:libafl>
)

add_library(libafl
  OBJECT
  "src/libafl.c"
  "afl-2.52b/afl-fuzz.c"
)

set(BIN_PATH ${CMAKE_CURRENT_BINARY_DIR})
set(AFL_PATH ${CMAKE_CURRENT_SOURCE_DIR}/afl-2.52b)

message(STATUS ${AFL_PATH})

set(CMAKE_C_FLAGS "-fPIC -DAFL_LIB -DBIN_PATH='\"${BIN_PATH}\"'")

target_include_directories(libafl PUBLIC ${AFL_PATH}/..)

target_link_libraries(afl PUBLIC dl)
