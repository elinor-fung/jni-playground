cmake_minimum_required(VERSION 3.15)
project(nativehost C)

set(CMAKE_C_STANDARD 99)

find_package(JNI REQUIRED)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${JNI_INCLUDE_DIRS}
)

set(SOURCES
    main.c
    pal_jni.c
)

add_executable(${PROJECT_NAME} ${SOURCES})
target_link_libraries(${PROJECT_NAME} ${JAVA_JVM_LIBRARY})

install(TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX})
if(WIN32)
    install(FILES $<TARGET_PDB_FILE:${PROJECT_NAME}> DESTINATION ${CMAKE_INSTALL_PREFIX})
endif(WIN32)
