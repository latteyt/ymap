cmake_minimum_required(VERSION 3.20)

project(ymap
  LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# =========================
# 可执行目标
# =========================
file(GLOB PROBE_MODULES "module/*.cpp")
add_executable(ymap
  ymap.cpp
  ${PROBE_MODULES}
)

target_compile_options(ymap PRIVATE
  -Wall
  -Werror
)

target_compile_options(ymap PRIVATE
  $<$<CONFIG:Debug>:-g>
  $<$<CONFIG:Release>:-O2>
)

# =========================
# include 路径（target级别）
# =========================
target_include_directories(ymap PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
)

# =========================
# pcap（优先用 pkg-config）
# =========================
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

target_include_directories(ymap PRIVATE
  ${PCAP_INCLUDE_DIRS}
)

target_link_libraries(ymap PRIVATE
  ${PCAP_LIBRARIES}
)

# =========================
# install（标准路径）
# =========================
include(GNUInstallDirs)

install(TARGETS ymap
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
