#
# Copyright 2021-2025 Software Radio Systems Limited
#
# This file is part of srsRAN
#
# srsRAN is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of
# the License, or (at your option) any later version.
#
# srsRAN is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# A copy of the GNU Affero General Public License can be found in
# the LICENSE file in the top-level directory of this distribution
# and at http://www.gnu.org/licenses/.
#

set_directory_properties(PROPERTIES LABELS "mark")

add_executable(mark_entity_test mark_entity_test.cpp)
target_link_libraries(mark_entity_test srsran_mark srsran_support srslog gtest gtest_main)
target_include_directories(mark_entity_test PRIVATE ${CMAKE_SOURCE_DIR})
gtest_discover_tests(mark_entity_test)

add_executable(ip_utils_test ip_utils_test.cpp)
target_link_libraries(ip_utils_test srsran_mark srsran_support srslog gtest gtest_main)
target_include_directories(ip_utils_test PRIVATE ${CMAKE_SOURCE_DIR})
gtest_discover_tests(ip_utils_test)

add_executable(mark_queue_model_test mark_queue_model_test.cpp)
target_link_libraries(mark_queue_model_test srsran_mark srsran_support srslog gtest gtest_main)
target_include_directories(mark_queue_model_test PRIVATE ${CMAKE_SOURCE_DIR})
gtest_discover_tests(mark_queue_model_test)

add_executable(mark_config_test mark_config_test.cpp)
target_link_libraries(mark_config_test srsran_cu_up_app_unit srsran_mark srsran_support srslog yaml-cpp gtest gtest_main)
target_include_directories(mark_config_test PRIVATE ${CMAKE_SOURCE_DIR})
gtest_discover_tests(mark_config_test)
