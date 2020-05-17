cmake_host_system_information(RESULT PROCESSOR_NAME QUERY PROCESSOR_NAME)

if (PROCESSOR_NAME MATCHES ".*AMD.*")
    add_definitions(-DX86_64_AMD_FAMILY)
endif()

add_subdirectory(linux)
