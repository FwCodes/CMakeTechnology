
#
# Copyright (C) The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

cmake_minimum_required(VERSION 3.4.1)

# configure import libs
set(distribution_DIR ${CMAKE_SOURCE_DIR}/../../../../distribution)

# if(${ANDROID_ABI} STRGREATER  arm})
#   set(arm armeabi-v7a)
# else()
#    set(arm x86)
# endif()
set(arm armeabi-v7a)

add_library(libBento4 STATIC IMPORTED)
set_target_properties(libBento4 PROPERTIES IMPORTED_LOCATION
    ${distribution_DIR}/${arm}/libBento4.a)


# shared lib will also be tucked into APK and sent to target
# refer to app/build.gradle, jniLibs section for that purpose.
# ${ANDROID_ABI} is handy for our purpose here. Probably this ${ANDROID_ABI} is
# the most valuable thing of this sample, the rest are pretty much normal cmake


# build application's shared lib
# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=gnu++11")

add_library(almalence-mp4editor SHARED
            almalence-mp4editor.cpp)

target_include_directories(almalence-mp4editor PRIVATE
                           ${distribution_DIR}/include/bento4)
target_link_libraries(almalence-mp4editor
                      libBento4
                      stdc++
                      android
                      dl
                      z
                      log)
