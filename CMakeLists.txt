#
# Copyright 2023 NXP
# SPDX-License-Identifier: Apache-2.0
#

CMAKE_MINIMUM_REQUIRED(VERSION 3.5.0)

PROJECT(sssProvider)

SET(SIMW_LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/simw_lib)
INCLUDE(${SIMW_LIB_DIR}/simw_lib.cmake)


IF("${PTMW_SE05X_Auth}" STREQUAL "None")
    FILE(
        GLOB
        SOURCES
        ${SIMW_SE_SOURCES}
        provider/*.c
        provider/*.h
    )
ELSE()
    FILE(
        GLOB
        SOURCES
        ${SIMW_SE_SOURCES}
        ${SIMW_SE_AUTH_SOURCES}
        provider/*.c
        provider/*.h
    )
ENDIF()

ADD_LIBRARY(${PROJECT_NAME} SHARED ${SOURCES})

TARGET_INCLUDE_DIRECTORIES(
	${PROJECT_NAME}
	PUBLIC
	${SIMW_INC_DIR}
)

ADD_CUSTOM_COMMAND(
    TARGET ${PROJECT_NAME}
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:${PROJECT_NAME}> ../bin
    COMMENT "Copy dll to bin"
)

INSTALL(TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_LIBDIR})
