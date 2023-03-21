cmake_minimum_required(VERSION 3.22)

project(SigmaProtocolSrc)

link_libraries(crypto)

aux_source_directory(. SRC_LIST)

add_library(SigmaProtocolSrc STATIC ${SRC_LIST})

add_executable(SigmaProtocolTest test_Sigma.cc)

target_link_libraries(SigmaProtocolTest PUBLIC
        SigmaProtocolSrc
        )