cmake_minimum_required(VERSION 3.2)
project(hepointer)

add_compile_options(-g) 
add_compile_options(-std=c++11)
add_compile_options(-march=native)
add_compile_options(-O2)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ".cmake")
#execute_process(COMMAND ${CMAKE_C_COMPILER} -v)


set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2 -Wall -Wextra -std=c99")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -std=c++11")

#-----------
# import GMP
#-----------

if (GMP_INCLUDE_DIR AND GMP_LIBRARIES)
  # Already in cache, be silent
  set(GMP_FIND_QUIETLY TRUE)
endif (GMP_INCLUDE_DIR AND GMP_LIBRARIES)

find_path(GMP_INCLUDE_DIR NAMES gmp.h )
find_library(GMP_LIBRARIES NAMES gmp libgmp )
find_library(GMPXX_LIBRARIES NAMES gmpxx libgmpxx )
MESSAGE(STATUS "GMP libs: " ${GMP_LIBRARIES} " " ${GMPXX_LIBRARIES} )

include(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(GMP DEFAULT_MSG GMP_INCLUDE_DIR GMP_LIBRARIES)

mark_as_advanced(GMP_INCLUDE_DIR GMP_LIBRARIES)

#-----------
# import openmp
#-----------

# list(INSERT CMAKE_MODULE_PATH 0 "${CMAKE_SOURCE_DIR}/../cmake")

find_package(OpenMP)
if (OPENMP_FOUND)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${GMP_C_FLAGS} ${OpenMP_C_FLAGS}")
    set(CMAKE_CXX_FLAGS "${CXXMAKE_CXX_FLAGS} ${GMP_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
endif()

#-----------
# add directories for libhcs 
#-----------
include_directories(${CMAKE_SOURCE_DIR}/../libhcs/include)


add_executable(foo "test.cpp" "libapcs.cpp")
target_link_libraries(foo ${GMP_LIBRARIES} ${GMPXX_LIBRARIES} ${CMAKE_SOURCE_DIR}/../libhcs/lib/libhcs.so)




