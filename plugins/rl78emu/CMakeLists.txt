cmake_minimum_required(VERSION 3.16)

if(NOT PROJECT_NAME)
    project(rl78emu LANGUAGES CXX)
    enable_testing()
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(RL78EMU_CORE_SOURCES
    src/cpu.cpp
    src/debugger.cpp
    src/disasm.cpp
    src/log.cpp
    src/machine.cpp
    src/memory.cpp
    src/module_path.cpp
    src/rl78_peripherals.cpp
)

add_library(rl78emu_core STATIC ${RL78EMU_CORE_SOURCES})

target_include_directories(rl78emu_core
    PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/src"
)

if(WIN32)
    target_compile_definitions(rl78emu_core PUBLIC _CRT_SECURE_NO_WARNINGS NOMINMAX)
    target_link_libraries(rl78emu_core PUBLIC ws2_32)
else()
    find_package(Threads REQUIRED)
    target_link_libraries(rl78emu_core PUBLIC Threads::Threads ${CMAKE_DL_LIBS})
endif()

get_filename_component(RL78EMU_REPO_ROOT_ABS "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
if(MSVC)
    file(TO_NATIVE_PATH "${CMAKE_CURRENT_SOURCE_DIR}" RL78EMU_SRC_PREFIX_NATIVE)
    file(TO_NATIVE_PATH "${RL78EMU_REPO_ROOT_ABS}" RL78EMU_REPO_ROOT_NATIVE)
    target_compile_options(rl78emu_core PUBLIC "/d1trimfile:${RL78EMU_SRC_PREFIX_NATIVE}")
    target_compile_options(rl78emu_core PUBLIC "/d1trimfile:${RL78EMU_REPO_ROOT_NATIVE}")
else()
    target_compile_options(rl78emu_core PUBLIC
        "-ffile-prefix-map=${CMAKE_CURRENT_SOURCE_DIR}/="
    )
endif()

add_executable(rl78emu src/main.cpp)
target_link_libraries(rl78emu PRIVATE rl78emu_core)

add_executable(rl78emu_tests tests/rl78emu_tests.cpp)
target_link_libraries(rl78emu_tests PRIVATE rl78emu_core)
add_test(NAME rl78emu_tests COMMAND rl78emu_tests)

if(MSVC)
    target_link_options(rl78emu PRIVATE $<$<CONFIG:Release>:/PDBALTPATH:%_PDB%>)
    target_link_options(rl78emu_tests PRIVATE $<$<CONFIG:Release>:/PDBALTPATH:%_PDB%>)
endif()

# Resolve IDA SDK root from IDASDK, IDA_SDK_DIR, in-repo SDK tree, or sibling checkout
set(_DEFAULT_IDA_SDK_DIR "")
if(DEFINED IDASDK AND EXISTS "${IDASDK}/include/idd.hpp")
    set(_DEFAULT_IDA_SDK_DIR "${IDASDK}")
elseif(DEFINED ENV{IDASDK} AND EXISTS "$ENV{IDASDK}/include/idd.hpp")
    set(_DEFAULT_IDA_SDK_DIR "$ENV{IDASDK}")
elseif(DEFINED ENV{IDA_SDK_DIR} AND EXISTS "$ENV{IDA_SDK_DIR}/include/idd.hpp")
    set(_DEFAULT_IDA_SDK_DIR "$ENV{IDA_SDK_DIR}")
elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../../../../include/idd.hpp")
    set(_DEFAULT_IDA_SDK_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../../..")
elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../../include/idd.hpp")
    set(_DEFAULT_IDA_SDK_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../..")
elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../../../ida-sdk-main/src/include/idd.hpp")
    set(_DEFAULT_IDA_SDK_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../../ida-sdk-main/src")
endif()
set(IDA_SDK_DIR "${_DEFAULT_IDA_SDK_DIR}" CACHE PATH "Path to IDA SDK src directory")

set(_IDA_LIB_PATH "")
if(EXISTS "${IDA_SDK_DIR}/lib/x64_win_64/ida.lib")
    set(_IDA_LIB_PATH "${IDA_SDK_DIR}/lib/x64_win_64/ida.lib")
elseif(EXISTS "${IDA_SDK_DIR}/lib/x64_win_vc_64/ida.lib")
    set(_IDA_LIB_PATH "${IDA_SDK_DIR}/lib/x64_win_vc_64/ida.lib")
endif()

if(TARGET idasdk::plugin OR (EXISTS "${IDA_SDK_DIR}/include/idd.hpp" AND _IDA_LIB_PATH))
    if(COMMAND ida_add_plugin)
        ida_add_plugin(rl78dbg
            SOURCES
                src/ida_dbg_plugin.cpp
            LIBRARIES
                rl78emu_core
        )
    else()
        add_library(rl78dbg SHARED src/ida_dbg_plugin.cpp)
        set_target_properties(rl78dbg PROPERTIES
            PREFIX ""
            OUTPUT_NAME "rl78dbg"
        )
        if(TARGET idasdk::plugin)
            target_link_libraries(rl78dbg PRIVATE rl78emu_core idasdk::plugin)
        else()
            target_include_directories(rl78dbg PRIVATE "${IDA_SDK_DIR}/include")
            target_compile_definitions(rl78dbg PRIVATE
                __NT__
                __EA64__
                __X64__
                _CRT_SECURE_NO_WARNINGS
                NOMINMAX
            )
            target_link_libraries(rl78dbg PRIVATE rl78emu_core "${_IDA_LIB_PATH}")
        endif()
    endif()

    if(MSVC)
        if(EXISTS "${IDA_SDK_DIR}/include/idd.hpp")
            get_filename_component(_IDA_SDK_DIR_ABS "${IDA_SDK_DIR}" ABSOLUTE)
            file(TO_NATIVE_PATH "${_IDA_SDK_DIR_ABS}" _IDA_SDK_DIR_NATIVE)
            target_compile_options(rl78dbg PRIVATE "/d1trimfile:${_IDA_SDK_DIR_NATIVE}")
        endif()
        target_link_options(rl78dbg PRIVATE $<$<CONFIG:Release>:/PDBALTPATH:%_PDB%>)
    else()
        if(EXISTS "${IDA_SDK_DIR}/include/idd.hpp")
            target_compile_options(rl78dbg PRIVATE "-ffile-prefix-map=${IDA_SDK_DIR}/=ida-sdk/")
        endif()
    endif()

    if(DEFINED ENV{APPDATA})
        set(_RL78_IDA_USER_DIR "$ENV{APPDATA}/Hex-Rays/IDA Pro")
        add_custom_command(TARGET rl78dbg POST_BUILD
            COMMAND "${CMAKE_COMMAND}" -E make_directory "${_RL78_IDA_USER_DIR}/plugins"
            COMMAND "${CMAKE_COMMAND}" -E copy_if_different
                "$<TARGET_FILE:rl78dbg>"
                "${_RL78_IDA_USER_DIR}/plugins/$<TARGET_FILE_NAME:rl78dbg>"
            COMMENT "Deploying rl78dbg plugin to IDA Pro user directory"
        )
    endif()
endif()
