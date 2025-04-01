cmake_minimum_required(VERSION 3.13.4)
project(kLLDB)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(LLVM REQUIRED CONFIG)
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")
include(AddLLVM)

include_directories(${LLVM_INCLUDE_DIRS})
separate_arguments(LLVM_DEFINITIONS_LIST NATIVE_COMMAND ${LLVM_DEFINITIONS})
add_definitions(${LLVM_DEFINITIONS_LIST})

add_subdirectory(plugins)

add_custom_target(copy_kLLDB_scripts ALL
  COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_BINARY_DIR}/bin"
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
    "${CMAKE_SOURCE_DIR}/kLLDB.sh" "${CMAKE_BINARY_DIR}/bin/kLLDB"
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
    "${CMAKE_SOURCE_DIR}/kLLDB.py" "${CMAKE_BINARY_DIR}/bin/kLLDB.py"
  COMMENT "Copying kLLDB.sh and kLLDB.py into build/bin"
)

add_dependencies(copy_kLLDB_scripts kLLDBLive)

install(TARGETS kLLDBLive
  LIBRARY DESTINATION lib
  RUNTIME DESTINATION bin
)

install(PROGRAMS
  "${CMAKE_SOURCE_DIR}/kLLDB.sh"
  DESTINATION bin
  RENAME kLLDB
)

install(FILES
  "${CMAKE_SOURCE_DIR}/kLLDB.py"
  DESTINATION bin
)
