project(rebuild)
cmake_minimum_required(VERSION 3.4.1)

add_definitions(-DNO_LOCALE_SUPPORT=True)

include_directories(.)

add_subdirectory(AndroidDef)
add_subdirectory(utils)

aux_source_directory(. RootSrc)

add_library(rebuild SHARED ${RootSrc} )

target_link_libraries(rebuild AndroidDef android c dl log Utils)

