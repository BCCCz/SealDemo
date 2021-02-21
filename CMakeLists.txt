cmake_minimum_required(VERSION 3.10)
project(SealDemo VERSION 1.0)
add_executable(sealdemo sealdemo.cpp)

find_package(SEAL)
target_link_libraries(sealdemo SEAL::seal)
