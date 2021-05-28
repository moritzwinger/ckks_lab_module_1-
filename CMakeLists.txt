cmake_minimum_required(VERSION 3.12)

project(AppliedCryptoFHELab LANGUAGES CXX)

# Import Microsoft SEAL
find_package(SEAL 3.6.5 EXACT REQUIRED)

add_executable(lab lab.cpp util.h)

if(TARGET SEAL::seal)
    target_link_libraries(lab PRIVATE SEAL::seal)
elseif(TARGET SEAL::seal_shared)
    target_link_libraries(lab PRIVATE SEAL::seal_shared)
else()
    message(FATAL_ERROR "Cannot find target SEAL::seal or SEAL::seal_shared")
endif()

add_subdirectory(seal_examples)
