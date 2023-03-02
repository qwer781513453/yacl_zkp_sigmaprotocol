cmake_minimum_required(VERSION 3.23)

project(SigmaProtocolSrc)

aux_source_directory(. SRC_LIST)

add_library(SigmaProtocolSrc STATIC ${SRC_LIST})

add_executable(SigmaProtocolTest test_Sigma.cc)

target_link_libraries(SigmaProtocolTest PUBLIC
        SigmaProtocolSrc
        )