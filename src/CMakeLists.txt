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