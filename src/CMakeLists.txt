set(COMPONENT_NAME gsp)

add_executable(${COMPONENT_NAME} 
  main.cpp
)

target_link_libraries(${COMPONENT_NAME} PUBLIC 
  Boost::boost 
  pthread
)

target_include_directories(${COMPONENT_NAME} PUBLIC 
	${Boost_INCLUDE_DIRS}
)