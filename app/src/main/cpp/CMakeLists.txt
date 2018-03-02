
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

#设置生成的so动态库最后输出的路径
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/../jniLibs/${ANDROID_ABI})

#添加子目录,将会调用子目录中的CMakeLists.txt

ADD_SUBDIRECTORY(bestshot)
ADD_SUBDIRECTORY(dro)
ADD_SUBDIRECTORY(groupshot)
ADD_SUBDIRECTORY(hdrprocessing)
ADD_SUBDIRECTORY(hiresportrait)
ADD_SUBDIRECTORY(histogram)
ADD_SUBDIRECTORY(nightprocessing)
ADD_SUBDIRECTORY(objectremoval)
ADD_SUBDIRECTORY(panorama)
ADD_SUBDIRECTORY(preshot)
ADD_SUBDIRECTORY(sequence)
ADD_SUBDIRECTORY(swapheap)
ADD_SUBDIRECTORY(utils)
ADD_SUBDIRECTORY(utils-jni)
ADD_SUBDIRECTORY(yuvimage)
ADD_SUBDIRECTORY(almashot)
ADD_SUBDIRECTORY(movingobjects)
ADD_SUBDIRECTORY(video)