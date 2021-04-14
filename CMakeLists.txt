cmake_minimum_required(VERSION 3.10)
project(SealDemo VERSION 1.0)
add_executable(sealdemo int_product.cpp)
add_executable(sealdemo2 1.cpp)


find_package(SEAL)
target_link_libraries(sealdemo SEAL::seal)
target_link_libraries(sealdemo2 SEAL::seal)


