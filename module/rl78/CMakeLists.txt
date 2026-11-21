# Processor Module: rl78
if(NOT COMMAND ida_add_procmod)
    cmake_minimum_required(VERSION 3.25)

    if(DEFINED ENV{IDASDK} AND NOT "$ENV{IDASDK}" STREQUAL "")
        set(_RL78_IDASDK_HINT "$ENV{IDASDK}")
    elseif(DEFINED IDASDK AND NOT "${IDASDK}" STREQUAL "")
        set(_RL78_IDASDK_HINT "${IDASDK}")
    elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../../../../include/pro.h")
        get_filename_component(_RL78_IDASDK_HINT "${CMAKE_CURRENT_SOURCE_DIR}/../../../.." ABSOLUTE)
        set(ENV{IDASDK} "${_RL78_IDASDK_HINT}")
    endif()

    if(_RL78_IDASDK_HINT AND EXISTS "${_RL78_IDASDK_HINT}/cmake/idasdk_standalone.cmake")
        include("${_RL78_IDASDK_HINT}/cmake/idasdk_standalone.cmake")
    endif()

    project(rl78_procmod LANGUAGES CXX)
    set(CMAKE_CXX_STANDARD 17)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)

    if(_RL78_IDASDK_HINT AND EXISTS "${_RL78_IDASDK_HINT}/cmake/idasdk_init.cmake")
        include("${_RL78_IDASDK_HINT}/cmake/idasdk_init.cmake")
    endif()
    find_package(idasdk REQUIRED HINTS "${_RL78_IDASDK_HINT}/cmake")
endif()

ida_add_procmod(rl78
    SOURCES
        ana.cpp
        emu.cpp
        ins.cpp
        merge.cpp
        out.cpp
        reg.cpp
        rl78.hpp
        ins.hpp
)

target_include_directories(rl78 PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

if(MSVC)
    get_filename_component(RL78_REPO_ROOT_ABS "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
    file(TO_NATIVE_PATH "${RL78_REPO_ROOT_ABS}" RL78_REPO_ROOT_NATIVE)
    file(TO_NATIVE_PATH "${CMAKE_CURRENT_SOURCE_DIR}" RL78_SRC_PREFIX_NATIVE)
    target_compile_options(rl78 PRIVATE "/d1trimfile:${RL78_SRC_PREFIX_NATIVE}")
    target_compile_options(rl78 PRIVATE "/d1trimfile:${RL78_REPO_ROOT_NATIVE}")
    if(DEFINED IDASDK AND EXISTS "${IDASDK}")
        get_filename_component(RL78_IDASDK_ABS "${IDASDK}" ABSOLUTE)
        file(TO_NATIVE_PATH "${RL78_IDASDK_ABS}" RL78_IDASDK_NATIVE)
        target_compile_options(rl78 PRIVATE "/d1trimfile:${RL78_IDASDK_NATIVE}")
    endif()
    target_link_options(rl78 PRIVATE $<$<CONFIG:Release>:/PDBALTPATH:%_PDB%>)
else()
    target_compile_options(rl78 PRIVATE
        "-ffile-prefix-map=${CMAKE_CURRENT_SOURCE_DIR}/="
    )
endif()

if(DEFINED ENV{APPDATA})
    set(IDA_USER_DIR "$ENV{APPDATA}/Hex-Rays/IDA Pro")

    add_custom_command(TARGET rl78 POST_BUILD
        COMMAND "${CMAKE_COMMAND}" -E make_directory "${IDA_USER_DIR}/procs"
        COMMAND "${CMAKE_COMMAND}" -E copy_if_different "$<TARGET_FILE:rl78>" "${IDA_USER_DIR}/procs/$<TARGET_FILE_NAME:rl78>"
        COMMAND "${CMAKE_COMMAND}" -E rm -f "${IDA_USER_DIR}/procs/rl78prox.dll"
        COMMENT "Deploying rl78 procmod to IDA Pro user directory"
    )
endif()
