cmake_minimum_required(VERSION 3.14)

# project variables
set(PROJECT_VERSION 1.0.0)
set(PROJECT_NAME egot)

# This is your project statement. You should always list languages;
project(
  ${PROJECT_NAME}
  VERSION ${PROJECT_VERSION}
  LANGUAGES CXX
)

# specify the C++ standard
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Find packages go here.
include(FetchContent)
find_package(Boost REQUIRED)
find_package(OpenSSL REQUIRED)

FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG        master
)

FetchContent_Declare(
  flecs
  GIT_REPOSITORY https://github.com/SanderMertens/flecs.git
  GIT_TAG        v2.3.2
)

FetchContent_MakeAvailable(googletest flecs)

# project dirs
add_subdirectory(src)
add_subdirectory(tests)