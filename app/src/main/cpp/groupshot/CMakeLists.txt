
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
set(gen_DIR ${CMAKE_SOURCE_DIR}/../../../../gen-libs)

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

add_library(libFFTEm SHARED IMPORTED)
set_target_properties(libFFTEm PROPERTIES IMPORTED_LOCATION
    ${distribution_DIR}/libFFTEm/lib/${arm}/libFFTEm.so)

add_library(libalmalib_eval STATIC IMPORTED)
set_target_properties(libalmalib_eval PROPERTIES IMPORTED_LOCATION
    ${CMAKE_SOURCE_DIR}/almashot/${arm}/libalmalib_eval.a)

# shared lib will also be tucked into APK and sent to target
# refer to app/build.gradle, jniLibs section for that purpose.
# ${ANDROID_ABI} is handy for our purpose here. Probably this ${ANDROID_ABI} is
# the most valuable thing of this sample, the rest are pretty much normal cmake


# build application's shared lib
# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=gnu++11")

add_library(almashot-seamless SHARED
            almashot-seamless.cpp FaceDetector.cpp)

target_include_directories(almashot-seamless PRIVATE
                           ${distribution_DIR}/include/almashot
                           ${gen_DIR}/src/main/cpp/FFTEm/FaceRecEm/common/src/b_FDSDK
                           ${gen_DIR}/src/main/cpp/FFTEm/FaceRecEm/common/src
                           ${gen_DIR}/src/main/cpp/FFTEm/Embedded/common/conf
                           ${gen_DIR}/src/main/cpp/FFTEm/Embedded/common/src
                           )

target_link_libraries(almashot-seamless
                      almalib
                      android
                      gomp
                      jpeg
                      utils-image
                      libFFTEm
                      libalmalib_eval
                      log
                      dl
                      z)
