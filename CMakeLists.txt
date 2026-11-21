# Processor Module: rl78prox
ida_add_procmod(rl78prox
    SOURCES
        ana.cpp
        emu.cpp
        ins.cpp
        merge.cpp
        out.cpp
        reg.cpp
        ../idaidp.hpp
        rl78.hpp
        ins.hpp
)

target_include_directories(rl78prox PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

if(MSVC)
    get_filename_component(RL78PROX_SDK_SRC_ABS "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
    file(TO_NATIVE_PATH "${RL78PROX_SDK_SRC_ABS}" RL78PROX_SDK_SRC_NATIVE)
    file(TO_NATIVE_PATH "${CMAKE_CURRENT_SOURCE_DIR}" RL78PROX_SRC_PREFIX_NATIVE)
    target_compile_options(rl78prox PRIVATE
        "/d1trimfile:${RL78PROX_SRC_PREFIX_NATIVE}\\"
        "/d1trimfile:${RL78PROX_SDK_SRC_NATIVE}\\"
    )
    target_link_options(rl78prox PRIVATE $<$<CONFIG:Release>:/PDBALTPATH:%_PDB%>)
else()
    target_compile_options(rl78prox PRIVATE
        "-ffile-prefix-map=${CMAKE_CURRENT_SOURCE_DIR}/="
    )
endif()

if(DEFINED ENV{APPDATA})
    set(IDA_USER_DIR "$ENV{APPDATA}/Hex-Rays/IDA Pro")

    add_custom_command(TARGET rl78prox POST_BUILD
        COMMAND "${CMAKE_COMMAND}" -E make_directory "${IDA_USER_DIR}/procs"
        COMMAND "${CMAKE_COMMAND}" -E copy_if_different "$<TARGET_FILE:rl78prox>" "${IDA_USER_DIR}/procs/$<TARGET_FILE_NAME:rl78prox>"
        COMMAND "${CMAKE_COMMAND}" -E copy_if_different "$<TARGET_FILE:rl78prox>" "${IDA_USER_DIR}/procs/rl78.dll"
        COMMENT "Deploying rl78prox procmod to IDA Pro user directory"
    )
endif()
