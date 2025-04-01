set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_library(LLDB_LIBRARY
    NAMES lldb LLDB
    HINTS /usr/lib/llvm-19/lib/
)

include_directories(/usr/lib/llvm-19/include/)

add_library(kLLDBLive SHARED kLLDBLive.cpp)

set_target_properties(kLLDBLive PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
  LIBRARY_OUTPUT_DIRECTORY  "${CMAKE_BINARY_DIR}/lib"
  RUNTIME_OUTPUT_DIRECTORY  "${CMAKE_BINARY_DIR}/bin"
)

find_library(KDUMPFILE_LIBRARY
    NAMES libkdumpfile.a
    HINTS /usr/local/lib /usr/lib
)
if(NOT KDUMPFILE_LIBRARY)
    message(FATAL_ERROR "Could not find libkdumpfile! Provide a HINTS or PATHS.")
endif()

find_library(ADDRXLAT_LIBRARY
    NAMES libaddrxlat.a
    HINTS /usr/local/lib /usr/lib
)
if(NOT ADDRXLAT_LIBRARY)
    message(FATAL_ERROR "Could not find libaddrxlat! Provide a HINTS or PATHS.")
endif()

message(STATUS "Found libkdumpfile at: ${KDUMPFILE_LIBRARY}")
message(STATUS "Found libaddrxlat at: ${ADDRXLAT_LIBRARY}")

add_library(kLLDBOffline SHARED kLLDBOffline.cpp)

target_link_libraries(kLLDBOffline PRIVATE
    ${LLDB_LIBRARY}
    ${KDUMPFILE_LIBRARY}
    ${ADDRXLAT_LIBRARY}
    z
)

set_target_properties(kLLDBOffline PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
  LIBRARY_OUTPUT_DIRECTORY  "${CMAKE_BINARY_DIR}/lib"
  RUNTIME_OUTPUT_DIRECTORY  "${CMAKE_BINARY_DIR}/bin"
)

install(TARGETS kLLDBLive
  LIBRARY DESTINATION lib
  RUNTIME DESTINATION bin
)

install(TARGETS kLLDBOffline
  LIBRARY DESTINATION lib
  RUNTIME DESTINATION bin
)
