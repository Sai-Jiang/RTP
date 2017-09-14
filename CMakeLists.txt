cmake_minimum_required(VERSION 3.8)
project(RTP)

set(CMAKE_C_STANDARD 99)

set(INClUDE_DIR ./include)
set(LIB_DIR ./lib)

include_directories(${INClUDE_DIR})
link_directories(${LIB_DIR})

link_libraries(kodoc)

add_executable(Sender ${SOURCE_FILES} Tx.c)
add_executable(Receiver ${SOURCE_FILES} Rx.c)

target_link_libraries(Sender kodoc)
target_link_libraries(Receiver kodoc)