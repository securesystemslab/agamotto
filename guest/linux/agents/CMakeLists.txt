add_executable(agent-exit agent-exit.c)

target_include_directories(
    agent-exit
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../../
)

add_executable(agent-get-prog agent-get-prog.c)

target_include_directories(
    agent-get-prog
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../../
)

add_executable(agent-chkpt agent-chkpt.c)

target_include_directories(
    agent-chkpt
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../../
)

add_executable(agent-next agent-next.c)

target_include_directories(
    agent-next
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../../
)


