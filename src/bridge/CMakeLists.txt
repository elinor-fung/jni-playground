cmake_minimum_required(VERSION 3.15)
project(bridge C)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${JNI_INCLUDE_DIRS}
)

set(HEADERS
    bridge.h
    pal_jni.h
    pal_x509.h
)

set(SOURCES
    bridge.c
    pal_jni.c
    pal_x509.c
)

add_library(${PROJECT_NAME} SHARED ${SOURCES})
target_link_libraries(${PROJECT_NAME} ${JAVA_JVM_LIBRARY})

install(TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX})
if(WIN32)
    install(FILES $<TARGET_PDB_FILE:${PROJECT_NAME}> DESTINATION ${CMAKE_INSTALL_PREFIX})
endif(WIN32)
