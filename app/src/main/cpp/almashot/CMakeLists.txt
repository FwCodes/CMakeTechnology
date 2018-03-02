
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

add_library(almalib-static STATIC IMPORTED)
set_target_properties(almalib-static PROPERTIES IMPORTED_LOCATION
    ${CMAKE_SOURCE_DIR}/almashot/${arm}/libalmalib_eval.a)

add_library(opencv_features2d STATIC IMPORTED)
set_target_properties(opencv_features2d PROPERTIES IMPORTED_LOCATION
    ${distribution_DIR}/OpenCV/libs/${arm}/libopencv_features2d.a)

add_library(opencv_imgproc STATIC IMPORTED)
set_target_properties(opencv_imgproc PROPERTIES IMPORTED_LOCATION
    ${distribution_DIR}/OpenCV/libs/${arm}/libopencv_imgproc.a)

add_library(opencv_calib3d STATIC IMPORTED)
set_target_properties(opencv_calib3d PROPERTIES IMPORTED_LOCATION
    ${distribution_DIR}/OpenCV/libs/${arm}/libopencv_calib3d.a)

add_library(opencv_video STATIC IMPORTED)
set_target_properties(opencv_video PROPERTIES IMPORTED_LOCATION
    ${distribution_DIR}/OpenCV/libs/${arm}/libopencv_video.a)

add_library(opencv_flann STATIC IMPORTED)
set_target_properties(opencv_flann PROPERTIES IMPORTED_LOCATION
    ${distribution_DIR}/OpenCV/libs/${arm}/libopencv_flann.a)

add_library(opencv_core STATIC IMPORTED)
set_target_properties(opencv_core PROPERTIES IMPORTED_LOCATION
    ${distribution_DIR}/OpenCV/libs/${arm}/libopencv_core.a)

add_library(opencv_tbb STATIC IMPORTED)
set_target_properties(opencv_tbb PROPERTIES IMPORTED_LOCATION
    ${distribution_DIR}/OpenCV/3rdparty/libs/${arm}/libtbb.a)

# shared lib will also be tucked into APK and sent to target
# refer to app/build.gradle, jniLibs section for that purpose.
# ${ANDROID_ABI} is handy for our purpose here. Probably this ${ANDROID_ABI} is
# the most valuable thing of this sample, the rest are pretty much normal cmake


# build application's shared lib
# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=gnu++11")

add_library(almalib SHARED
            stub.cpp)

target_include_directories(almalib PRIVATE
                           ${distribution_DIR}/include/almashot)

target_link_libraries(almalib
                      android
                      gomp
                      opencv_features2d
                      opencv_imgproc
                      opencv_calib3d
                      opencv_video
                      opencv_flann
                      opencv_core
                      opencv_tbb
                      almalib-static
                      stdc++
                      log
                      dl
                      z
                      EGL
                      GLESv2)
