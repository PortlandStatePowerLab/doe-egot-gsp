add_subdirectory(ecs)
add_subdirectory(https)

set(COMPONENT_NAME gsp)
add_library(${COMPONENT_NAME} STATIC
    main.cpp
)

target_link_libraries(${COMPONENT_NAME} PUBLIC 
  https_server
  ecs_server
  pthread
)

target_include_directories(${COMPONENT_NAME} PUBLIC 
  ${https_server_INCLUDE_DIRS}
  ${ecs_server_INCLUDE_DIRS}
)

add_custom_command(
    TARGET ${COMPONENT_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
    ${CMAKE_SOURCE_DIR}/resources/ ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
)

# install the target and create export-set
install(
    TARGETS ${COMPONENT_NAME}
    EXPORT ${COMPONENT_NAME}Targets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
    INCLUDES DESTINATION include
)

install(
    EXPORT ${COMPONENT_NAME}Targets
    FILE ${COMPONENT_NAME}Targets.cmake
    NAMESPACE ${PROJECT_NAME}::
    DESTINATION lib/cmake
)