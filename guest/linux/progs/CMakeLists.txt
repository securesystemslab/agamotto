file(GLOB prog_C_SRC
    "*.c"
)

foreach(prog_C ${prog_C_SRC})
    get_filename_component(prog_C ${prog_C} NAME)
    string(REPLACE ".c" "" prog_NOEXT ${prog_C})
    add_executable(${prog_NOEXT} ${prog_C})
    target_include_directories(
        ${prog_NOEXT}
        PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/../../
    )
endforeach()

file(GLOB prog_SH_SRC
    "*.sh"
)

foreach(prog_SH ${prog_SH_SRC})
    get_filename_component(prog_SH ${prog_SH} NAME)
    string(REPLACE ".sh" "" prog_NOEXT ${prog_SH})
    add_custom_target(${prog_NOEXT} ALL)
    add_custom_command(
        TARGET ${prog_NOEXT}
        COMMAND ${CMAKE_COMMAND} -E copy
                ${CMAKE_CURRENT_SOURCE_DIR}/${prog_SH}
                ${CMAKE_CURRENT_BINARY_DIR}/${prog_NOEXT}
    )
endforeach()
