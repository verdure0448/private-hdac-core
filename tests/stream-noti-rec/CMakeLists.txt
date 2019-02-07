cmake_minimum_required(VERSION 3.1)

add_executable(stream-noti-rec
main.cpp)

set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}" ${CMAKE_MODULE_PATH})
include(FindZmqpp)
include(FindPkgConfig)

find_package(Zmqpp REQUIRED)
pkg_check_modules(ZMQ REQUIRED libzmq)


target_link_libraries(stream-noti-rec
    PUBLIC
    ${ZMQPP_LIBRARIES}
    ${ZMQ_LIBRARIES}
)