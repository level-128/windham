set(PROJECT_ROOT ${CMAKE_SOURCE_DIR})
set(KCONFIG_ROOT ${CMAKE_SOURCE_DIR}/Kconfig)
set(AUTOCONF_H ${CMAKE_CURRENT_BINARY_DIR}/kconfig/include/generated/autoconf.h)
set(BOARD_DEFCONFIG ${CMAKE_SOURCE_DIR}/configs/${ARCH}_defconfig)

# Re-configure (Re-execute all CMakeLists.txt code) when autoconf.h changes
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${AUTOCONF_H})

include(cmakelib/extensions.cmake)
include(cmakelib/python.cmake)
include(cmakelib/kconfig.cmake)

