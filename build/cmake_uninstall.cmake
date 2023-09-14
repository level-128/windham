if(NOT EXISTS "/home/level-128/CLionProjects/ienc/build/install_manifest.txt")
    message(FATAL_ERROR "Cannot find install manifest: /home/level-128/CLionProjects/ienc/build/install_manifest.txt")
endif()

file(READ "/home/level-128/CLionProjects/ienc/build/install_manifest.txt" files)
string(REGEX REPLACE "\n" ";" files "${files}")
foreach(file ${files})
    message(STATUS "Uninstalling \"$ENV{DESTDIR}${file}\"")
    if(EXISTS "$ENV{DESTDIR}${file}")
        execute_process(
            COMMAND /usr/bin/cmake -E remove "$ENV{DESTDIR}${file}"
            RESULT_VARIABLE rm_err
            OUTPUT_VARIABLE rm_out
            )
        if(NOT ${rm_err} EQUAL 0)
            message(FATAL_ERROR "Problem when removing \"$ENV{DESTDIR}${file}\"")
        endif()
    else()
        message(STATUS "File \"$ENV{DESTDIR}${file}\" does not exist.")
    endif()
endforeach()
