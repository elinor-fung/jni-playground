cmake_minimum_required(VERSION 3.15)
project(nativehost C)

# https://gitlab.kitware.com/cmake/community/-/wikis/doc/cmake/RPATH-handling
set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)
if(APPLE)
    set(MACOSX_RPATH ON)
    set(CMAKE_INSTALL_RPATH "@loader_path")
else()
    set(CMAKE_INSTALL_RPATH "\$ORIGIN")
endif()

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/../bridge
    ${JNI_INCLUDE_DIRS}
)

set(SOURCES
    main.c
)

add_executable(${PROJECT_NAME} ${SOURCES})
target_link_libraries(${PROJECT_NAME} bridge)

install(TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX})
if(WIN32)
    install(FILES $<TARGET_PDB_FILE:${PROJECT_NAME}> DESTINATION ${CMAKE_INSTALL_PREFIX})
endif(WIN32)
