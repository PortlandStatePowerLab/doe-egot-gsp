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
find_package(Boost REQUIRED)
find_package(OpenSSL REQUIRED)

# project dirs
add_subdirectory(src)
add_subdirectory(tests)