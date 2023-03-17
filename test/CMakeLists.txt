CMAKE_MINIMUM_REQUIRED(VERSION 3.15)
PROJECT(${CMAKE_PROJECT_NAME}_test CXX)

SET(CMAKE_CXX_STANDARD 17)

SET(LIB_PATH "${CMAKE_INSTALL_PREFIX}/lib")
IF(UNIX)
    FIND_PACKAGE(GTest REQUIRED)
ELSE()
    FIND_PACKAGE(GTest REQUIRED PATHS "${CMAKE_INSTALL_PREFIX}/lib/cmake/GTest" REQUIRED)
ENDIF()
FIND_LIBRARY(GMOCK_LIB gmock.lib libgmock.a PATHS "${LIB_PATH}" REQUIRED)
FIND_PACKAGE(Threads REQUIRED)
ADD_DEFINITIONS("-DGTEST_HAS_PTHREAD=0")

SET(PROJECT_BASE_LIBRARIES
        ${FMT_LIB}
        ${GTEST_BOTH_LIBRARIES}
        ${GMOCK_LIB}
        ${SPDLOG_LIB}
        )
INCLUDE_DIRECTORIES(BEFORE
        ${GTEST_INCLUDE_DIRS}
        ${CMAKE_INSTALL_PREFIX}/include
        ${PROJECT_SOURCE_DIR}/../src
        )

ADD_EXECUTABLE(${PROJECT_NAME}
        gtest_main.cpp
        ../src/ipconverter.cpp
        src/ipconverMock.cpp
        src/UTipConverter.cpp
        )

TARGET_LINK_LIBRARIES(${PROJECT_NAME}
        ${GTEST_BOTH_LIBRARIES}
        ${GMOCK_LIB}
        ${FMT_LIB}
        ${CMAKE_THREAD_LIBS_INIT}
        ${Boost_LIBRARIES}
        ${LIB_CURL}
        ${LIB_CPR}
        )

INSTALL(TARGETS
        ${PROJECT_NAME}
        RUNTIME DESTINATION test
        )

# # Locate GTest
# find_package(GTest REQUIRED)
# include_directories(${GTEST_INCLUDE_DIRS})

# # Link runTests with what we want to test and the GTest and pthread library
# add_executable(IpConverterTest ipconverterMock.cpp UTipConverter.cpp)
# target_link_libraries(runTests ${GTEST_LIBRARIES} pthread)
