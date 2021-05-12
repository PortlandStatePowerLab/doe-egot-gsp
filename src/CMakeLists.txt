add_subdirectory(ecs)
add_subdirectory(https)

set(COMPONENT_NAME gsp)

add_executable(${COMPONENT_NAME} 
  main.cpp
)

target_link_libraries(${COMPONENT_NAME} PUBLIC 
  https
  ecs
  pthread
)

target_include_directories(${COMPONENT_NAME} PUBLIC 
  ${https_INCLUDE_DIRS}
  ${ecs_INCLUDE_DIRS}
)

add_custom_command(
    TARGET ${COMPONENT_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
    ${CMAKE_SOURCE_DIR}/resources/ ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
)

# include CMakePackageConfigHelpers macro
include(CMakePackageConfigHelpers)

write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion 
)

configure_package_config_file(
    ${PROJECT_NAME}Config.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake
    INSTALL_DESTINATION lib/cmake
)

install(
    FILES ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake
    DESTINATION lib/cmake
)