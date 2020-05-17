file(GLOB executor_C_SRC
    "*.c"
)

foreach(executor_C ${executor_C_SRC})
    get_filename_component(executor_C ${executor_C} NAME)
    string(REPLACE "executor" "syz-executor" syz_executor_C ${executor_C})
    string(REPLACE ".c" "" syz_executor_NOEXT ${syz_executor_C})
    add_executable(${syz_executor_NOEXT} ${executor_C})
    message(${CMAKE_CURRENT_SOURCE_DIR})
    target_include_directories(
        ${syz_executor_NOEXT}
        PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/../../
    )
    target_link_libraries(${syz_executor_NOEXT} rt)
endforeach()


file(GLOB executor_SH_SRC
    "*.sh"
)

foreach(executor_SH ${executor_SH_SRC})
    get_filename_component(executor_SH ${executor_SH} NAME)
    string(REPLACE "executor" "syz-executor" syz_executor_SH ${executor_SH})
    string(REPLACE ".sh" "" syz_executor_NOEXT ${syz_executor_SH})
    add_custom_target(${syz_executor_NOEXT} ALL)
    add_custom_command(
        TARGET ${syz_executor_NOEXT}
        COMMAND ${CMAKE_COMMAND} -E copy
                ${CMAKE_CURRENT_SOURCE_DIR}/${executor_SH}
                ${CMAKE_CURRENT_BINARY_DIR}/${syz_executor_NOEXT}
    )
endforeach()
