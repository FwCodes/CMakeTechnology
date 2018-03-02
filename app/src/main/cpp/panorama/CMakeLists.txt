
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

add_library(gomp STATIC IMPORTED)
set_target_properties(gomp PROPERTIES IMPORTED_LOCATION
    ${distribution_DIR}/${arm}/libgomp.a)

add_library(jpeg STATIC IMPORTED)
set_target_properties(jpeg PROPERTIES IMPORTED_LOCATION
    ${distribution_DIR}/${arm}/libjpeg.a)

add_library(libalmalib_eval STATIC IMPORTED)
set_target_properties(libalmalib_eval PROPERTIES IMPORTED_LOCATION
    ${CMAKE_SOURCE_DIR}/almashot/${arm}/libalmalib_eval.a)

# shared lib will also be tucked into APK and sent to target
# refer to app/build.gradle, jniLibs section for that purpose.
# ${ANDROID_ABI} is handy for our purpose here. Probably this ${ANDROID_ABI} is
# the most valuable thing of this sample, the rest are pretty much normal cmake


# build application's shared lib
# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=gnu++11")

add_library(almashot-pano SHARED
            almashot-pano.cpp VFGyro-jni.cpp)

target_include_directories(almashot-pano PRIVATE
                           ${distribution_DIR}/include/almashot
                           )

target_link_libraries(almashot-pano
                      almalib
                      android
                      libalmalib_eval
                      gomp
                      jpeg
                      stdc++
                      log
                      dl
                      z)
