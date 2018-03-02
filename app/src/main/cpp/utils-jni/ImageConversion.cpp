/*
The contents of this file are subject to the Mozilla Public License
Version 1.1 (the "License"); you may not use this file except in
compliance with the License. You may obtain a copy of the License at
http://www.mozilla.org/MPL/

Software distributed under the License is distributed on an "AS IS"
basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
License for the specific language governing rights and limitations
under the License.

The Original Code is collection of files collectively known as Open Camera.

The Initial Developer of the Original Code is Almalence Inc.
Portions created by Initial Developer are Copyright (C) 2013
by Almalence Inc. All Rights Reserved.
*/

#include <math.h>
#include <string.h>
#include <stdio.h>
#include <jni.h>
#include <android/log.h>
#include <malloc.h>

#include "../utils/ImageConversionUtils.h"

#define BMP_R(p)	((p) & 0xFF)
#define BMP_G(p)	(((p)>>8) & 0xFF)
#define BMP_B(p)	(((p)>>16)& 0xFF)

jbyte NightGamma[511] =
{
        0, 1, 2, 3, 4, 5, 6, 6, 7, 8, 9, 10, 11, 12, 13, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 23, 24, 24, 25, 26, 27, 28, 29, 29, 30, 31,
        32, 33, 33, 34, 35, 36, 37, 38, 38, 39, 40, 41, 42, 42, 43, 44, 45, 46, 46, 47, 48, 49, 50, 50, 51, 52, 53, 54, 54, 55, 56, 57, 58, 58, 59, 60, 61, 61, 62, 63,
        64, 65, 65, 66, 67, 68, 68, 69, 70, 71, 71, 72, 73, 74, 75, 75, 76, 77, 78, 78, 79, 80, 81, 81, 82, 83, 84, 84, 85, 86, 87, 87, 88, 89, 90, 90, 91, 92, 93, 93, 94, 95,
        96, 96, 97, 98, 98, 99, 100, 101, 101, 102, 103, 104, 104, 105, 106, 106, 107, 108, 109, 109, 110, 111, 111, 112, 113, 113, 114, 115, 116, 116, 117, 118, 118,
        119, 120, 120, 121, 122, 123, 123, 124, 125, 125, 126, 127, 127, (jbyte) 128, (jbyte) 129, (jbyte) 129, (jbyte) 130, (jbyte) 131, (jbyte) 131, (jbyte) 132, (jbyte) 133, (jbyte) 133, (jbyte) 134, (jbyte) 135, (jbyte) 135, (jbyte) 136, (jbyte) 137, (jbyte) 137, (jbyte) 138, (jbyte) 139, (jbyte) 139, (jbyte) 140,
        (jbyte) 141, (jbyte) 141, (jbyte) 142, (jbyte) 143, (jbyte) 143, (jbyte) 144, (jbyte) 144, (jbyte) 145, (jbyte) 146, (jbyte) 146, (jbyte) 147, (jbyte) 148, (jbyte) 148, (jbyte) 149, (jbyte) 150, (jbyte) 150, (jbyte) 151, (jbyte) 151, (jbyte) 152, (jbyte) 153, (jbyte) 153, (jbyte) 154, (jbyte) 155, (jbyte) 155, (jbyte) 156, (jbyte) 156, (jbyte) 157, (jbyte) 158, (jbyte) 158, (jbyte) 159, (jbyte) 159, (jbyte) 160,
        (jbyte) 161, (jbyte) 161, (jbyte) 162, (jbyte) 163, (jbyte) 163, (jbyte) 164, (jbyte) 164, (jbyte) 165, (jbyte) 165, (jbyte) 166, (jbyte) 167, (jbyte) 167, (jbyte) 168, (jbyte) 168, (jbyte) 169, (jbyte) 170, (jbyte) 170, (jbyte) 171, (jbyte) 171, (jbyte) 172, (jbyte) 172, (jbyte) 173, (jbyte) 174, (jbyte) 174, (jbyte) 175, (jbyte) 175, (jbyte) 176, (jbyte) 176, (jbyte) 177, (jbyte) 178, (jbyte) 178, (jbyte) 179,
        (jbyte) 179, (jbyte) 180, (jbyte) 180, (jbyte) 181, (jbyte) 181, (jbyte) 182, (jbyte) 182, (jbyte) 183, (jbyte) 184, (jbyte) 184, (jbyte) 185, (jbyte) 185, (jbyte) 186, (jbyte) 186, (jbyte) 187, (jbyte) 187, (jbyte) 188, (jbyte) 188, (jbyte) 189, (jbyte) 189, (jbyte) 190, (jbyte) 190, (jbyte) 191, (jbyte) 191, (jbyte) 192, (jbyte) 192, (jbyte) 193, (jbyte) 193, (jbyte) 194, (jbyte) 194, (jbyte) 195, (jbyte) 195,
        (jbyte) 196, (jbyte) 196, (jbyte) 197, (jbyte) 197, (jbyte) 198, (jbyte) 198, (jbyte) 199, (jbyte) 199, (jbyte) 200, (jbyte) 200, (jbyte) 201, (jbyte) 201, (jbyte) 202, (jbyte) 202, (jbyte) 203, (jbyte) 203, (jbyte) 204, (jbyte) 204, (jbyte) 205, (jbyte) 205, (jbyte) 205, (jbyte) 206, (jbyte) 206, (jbyte) 207, (jbyte) 207, (jbyte) 208, (jbyte) 208, (jbyte) 209, (jbyte) 209, (jbyte) 210, (jbyte) 210, (jbyte) 210,
        (jbyte) 211, (jbyte) 211, (jbyte) 212, (jbyte) 212, (jbyte) 213, (jbyte) 213, (jbyte) 213, (jbyte) 214, (jbyte) 214, (jbyte) 215, (jbyte) 215, (jbyte) 215, (jbyte) 216, (jbyte) 216, (jbyte) 217, (jbyte) 217, (jbyte) 218, (jbyte) 218, (jbyte) 218, (jbyte) 219, (jbyte) 219, (jbyte) 220, (jbyte) 220, (jbyte) 220, (jbyte) 221, (jbyte) 221, (jbyte) 221, (jbyte) 222, (jbyte) 222, (jbyte) 223, (jbyte) 223, (jbyte) 223,
        (jbyte) 224, (jbyte) 224, (jbyte) 224, (jbyte) 225, (jbyte) 225, (jbyte) 226, (jbyte) 226, (jbyte) 226, (jbyte) 227, (jbyte) 227, (jbyte) 227, (jbyte) 228, (jbyte) 228, (jbyte) 228, (jbyte) 229, (jbyte) 229, (jbyte) 229, (jbyte) 230, (jbyte) 230, (jbyte) 230, (jbyte) 231, (jbyte) 231, (jbyte) 231, (jbyte) 232, (jbyte) 232, (jbyte) 232, (jbyte) 233, (jbyte) 233, (jbyte) 233, (jbyte) 234, (jbyte) 234, (jbyte) 234,
        (jbyte) 234, (jbyte) 235, (jbyte) 235, (jbyte) 235, (jbyte) 236, (jbyte) 236, (jbyte) 236, (jbyte) 237, (jbyte) 237, (jbyte) 237, (jbyte) 237, (jbyte) 238, (jbyte) 238, (jbyte) 238, (jbyte) 238, (jbyte) 239, (jbyte) 239, (jbyte) 239, (jbyte) 240, (jbyte) 240, (jbyte) 240, (jbyte) 240, (jbyte) 241, (jbyte) 241, (jbyte) 241, (jbyte) 241, (jbyte) 242, (jbyte) 242, (jbyte) 242, (jbyte) 242, (jbyte) 243, (jbyte) 243,
        (jbyte) 243, (jbyte) 243, (jbyte) 244, (jbyte) 244, (jbyte) 244, (jbyte) 244, (jbyte) 244, (jbyte) 245, (jbyte) 245, (jbyte) 245, (jbyte) 245, (jbyte) 245, (jbyte) 246, (jbyte) 246, (jbyte) 246, (jbyte) 246, (jbyte) 246, (jbyte) 247, (jbyte) 247, (jbyte) 247, (jbyte) 247, (jbyte) 247, (jbyte) 248, (jbyte) 248, (jbyte) 248, (jbyte) 248, (jbyte) 248, (jbyte) 249, (jbyte) 249, (jbyte) 249, (jbyte) 249, (jbyte) 249,
        (jbyte) 249, (jbyte) 250, (jbyte) 250, (jbyte) 250, (jbyte) 250, (jbyte) 250, (jbyte) 250, (jbyte) 250, (jbyte) 251, (jbyte) 251, (jbyte) 251, (jbyte) 251, (jbyte) 251, (jbyte) 251, (jbyte) 251, (jbyte) 252, (jbyte) 252, (jbyte) 252, (jbyte) 252, (jbyte) 252, (jbyte) 252, (jbyte) 252, (jbyte) 252, (jbyte) 252, (jbyte) 253, (jbyte) 253, (jbyte) 253, (jbyte) 253, (jbyte) 253, (jbyte) 253, (jbyte) 253, (jbyte) 253,
        (jbyte) 253, (jbyte) 253, (jbyte) 254, (jbyte) 254, (jbyte) 254, (jbyte) 254, (jbyte) 254, (jbyte) 254, (jbyte) 254, (jbyte) 254, (jbyte) 254, (jbyte) 254, (jbyte) 254, (jbyte) 254, (jbyte) 254, (jbyte) 254, (jbyte) 254, (jbyte) 254, (jbyte) 255, (jbyte) 255, (jbyte) 255, (jbyte) 255, (jbyte) 255, (jbyte) 255, (jbyte) 255, (jbyte) 255, (jbyte) 255, (jbyte) 255, (jbyte) 255, (jbyte) 255, (jbyte) 255, (jbyte) 255,
        (jbyte) 255, (jbyte) 255, (jbyte) 255, (jbyte) 255, (jbyte) 255, (jbyte) 255, (jbyte) 255
};

// summation with tone-curve applied after
// used in night-mode viewfinder
extern "C" JNIEXPORT void JNICALL Java_com_almalence_util_ImageConversion_sumByteArraysNV21
(
	JNIEnv* env,
	jobject thiz,
	jbyteArray data1,
	jbyteArray data2,
	jbyteArray out,
	jint width,
	jint height
)
{
	jbyte* frame1 = env->GetByteArrayElements(data1, 0);
	jbyte* frame2 = env->GetByteArrayElements(data2, 0);
	jbyte* frame_res = env->GetByteArrayElements(out, 0);

	jint frameSize = width * height;

	for (jint j = 0, yp = 0; j < height; j++) {

		jint uvp1 = frameSize + (j >> 1) * width, u1 = 0, v1 = 0;
		jint uvp2 = frameSize + (j >> 1) * width, u2 = 0, v2 = 0;

	  for (jint i = 0; i < width; i++, yp++) {
		jint y1 = (0xff & ((jint) frame1[yp]));
		jint y2 = (0xff & ((jint) frame2[yp]));


		if ((i & 1) == 0) {
		  v1 = (0xff & frame1[uvp1++]) - 128;
		  u1 = (0xff & frame1[uvp1++]) - 128;
		  v2 = (0xff & frame2[uvp2++]) - 128;
		  u2 = (0xff & frame2[uvp2++]) - 128;


		  jint v0 = (v1+v2)/2;
		  jint u0 = (u1+u2)/2;
		  frame_res[uvp1-1] = (jbyte)((u0+128));
		  frame_res[uvp1-2] = (jbyte)((v0+128));
		}
		//jint y0 = (y1+y2) < 255 ? (y1+y2) : 255;
		frame_res[yp] = NightGamma[y1+y2]; // (jbyte)(y0);
	  }
	}

	env->ReleaseByteArrayElements(out, frame_res, 0);
	env->ReleaseByteArrayElements(data2, frame2, 0);
	env->ReleaseByteArrayElements(data1, frame1, 0);
}


extern "C" JNIEXPORT void JNICALL Java_com_almalence_util_ImageConversion_TransformNV21
(
	JNIEnv* env,
	jobject thiz,
	jbyteArray InPic,
	jbyteArray OutPic,
	int sx,
	int sy,
	int flipLR,
	int flipUD,
	int rotate90
)
{
	jbyte * InNV21 = env->GetByteArrayElements(InPic, 0);
	jbyte * OutNV21;

	if (OutPic != InPic) OutNV21 = env->GetByteArrayElements(OutPic, 0);
		else OutNV21 = InNV21;

	TransformNV21((unsigned char*)InNV21, (unsigned char*)OutNV21, sx, sy, NULL, flipLR, flipUD, rotate90);

	if (OutPic != InPic)
		env->ReleaseByteArrayElements(OutPic, OutNV21, JNI_ABORT);
	env->ReleaseByteArrayElements(InPic, InNV21, JNI_ABORT);

}

extern "C" JNIEXPORT void JNICALL Java_com_almalence_util_ImageConversion_TransformNV21N
(
	JNIEnv* env,
	jobject thiz,
	int InPic,
	int OutPic,
	int sx,
	int sy,
	int flipLR,
	int flipUD,
	int rotate90
)
{
	TransformNV21((unsigned char*)InPic, (unsigned char*)OutPic, sx, sy, NULL, flipLR, flipUD, rotate90);
}


extern "C" JNIEXPORT jint JNICALL Java_com_almalence_util_ImageConversion_JpegConvert
(
	JNIEnv* env,
	jobject thiz,
	jbyteArray jdata,
	jint sx,
	jint sy,
	jboolean jrot,
	jboolean mirror,
	jint rotationDegree
)
{
	int data_length;
	unsigned char *data;

	data_length = env->GetArrayLength(jdata);
	data = (unsigned char*)env->GetByteArrayElements(jdata, NULL);

	unsigned char* out = (unsigned char*)malloc(sx*sy+2*((sx+1)/2)*((sy+1)/2));

	if (out != NULL)
	{
		if (JPEG2NV21(out, data, data_length, sx, sy, jrot, mirror, rotationDegree) == 0)
		{
			free(out);
			out = NULL;
		}
	}

	env->ReleaseByteArrayElements(jdata, (jbyte*)data, JNI_ABORT);

	return (jint)out;
}

extern "C" JNIEXPORT jint JNICALL Java_com_almalence_util_ImageConversion_JpegConvertN
(
	JNIEnv* env,
	jobject thiz,
	jint jpeg,
	jint jpeg_length,
	jint sx,
	jint sy,
	jboolean jrot,
	jboolean mirror,
	jint rotationDegree
)
{
	int data_length;
	unsigned char *data;

	unsigned char* out = (unsigned char*)malloc(sx*sy+2*((sx+1)/2)*((sy+1)/2));

	if (out != NULL)
	{
		if (JPEG2NV21(out, (unsigned char*)jpeg, jpeg_length, sx, sy, jrot, mirror, rotationDegree) == 0)
		{
			free(out);
			out = NULL;
		}
	}

	return (jint)out;
}

extern "C" JNIEXPORT void JNICALL Java_com_almalence_util_ImageConversion_convertNV21toGLN(
		JNIEnv *env, jclass clazz, jint ain, jbyteArray aout, jint width,	jint height, jint outWidth, jint outHeight)
{
	jbyte *cImageOut = env->GetByteArrayElements(aout, 0);

	NV21_to_RGB_scaled_rotated((unsigned char*)ain, width, height, 0, 0, width, height, outWidth, outHeight, 4, (unsigned char*)cImageOut);

	env->ReleaseByteArrayElements(aout, cImageOut, 0);
}

extern "C" JNIEXPORT void JNICALL Java_com_almalence_util_ImageConversion_convertNV21toGL(
		JNIEnv *env, jclass clazz, jbyteArray ain, jbyteArray aout, jint width,	jint height, jint outWidth, jint outHeight)
{
	jbyte *cImageIn = env->GetByteArrayElements(ain, 0);
	jbyte *cImageOut = env->GetByteArrayElements(aout, 0);

	NV21_to_RGB_scaled_rotated((unsigned char*)cImageIn, width, height, 0, 0, width, height, outWidth, outHeight, 5, (unsigned char*)cImageOut);

	env->ReleaseByteArrayElements(ain, cImageIn, 0);
	env->ReleaseByteArrayElements(aout, cImageOut, 0);
}

extern "C" JNIEXPORT void JNICALL Java_com_almalence_util_ImageConversion_resizeJpeg2RGBA(
		JNIEnv *env, jclass clazz,
		jint jpeg,
		jint jpeg_length,
		jbyteArray rgb_out,
		jint inHeight, jint inWidth,
		jint outWidth, jint outHeight,
		jboolean mirror)
{
	unsigned int * data_rgba = (unsigned int*)malloc(inHeight*inWidth*sizeof(unsigned int));
	if (data_rgba == NULL)
	{
		__android_log_print(ANDROID_LOG_ERROR, "Almalence", "nativeresizeJpeg2RGBA(): malloc() returned NULL");
		return;
	}

	JPEG2RGBA((unsigned char*)data_rgba, (unsigned char*)jpeg, jpeg_length);

	unsigned char * rgb_bytes = (unsigned char*)env->GetByteArrayElements(rgb_out, 0);

	const int tripleHeight = (outHeight - 1) * 4;
	int yoffset = tripleHeight;
	int cr, cb, cg;
	int offset;

	// down-scaling with area averaging gives a higher-quality result comparing to skia scaling
	int navg = max(1, 3*max(inWidth/outWidth, inHeight/outHeight)/2);
	int norm = 65536/(navg*navg);

	for (int i = 0; i < outHeight; i++)
	{
		offset = yoffset;

		int ys = i*inHeight/outHeight;
		int ye = min(ys+navg, inHeight);

		for (int j = 0; j < outWidth; j++)
		{
			int xs = j*inWidth/outWidth;
			int xe = min(xs+navg, inWidth);

			cr = cb = cg = 0;
			for (int ii=ys; ii<ye; ++ii)
				for (int jj=xs; jj<xe; ++jj)
				{
					cr += BMP_R(data_rgba[ii * inWidth + jj]);
					cg += BMP_G(data_rgba[ii * inWidth + jj]);
					cb += BMP_B(data_rgba[ii * inWidth + jj]);
				}

			cr = norm*cr/65536;
			cg = norm*cg/65536;
			cb = norm*cb/65536;

			rgb_bytes[offset++] = cr;
			rgb_bytes[offset++] = cg;
			rgb_bytes[offset++] = cb;
			rgb_bytes[offset++] = 255;

			offset += tripleHeight;
		}

		yoffset -= 4;
	}

	free (data_rgba);

	addRoundCornersRGBA8888(rgb_bytes, outWidth, outHeight);

	if (mirror)
	{
		TransformPlane32bit((unsigned int*)rgb_bytes, (unsigned int*)rgb_bytes, outWidth, outHeight, 0, 1, 0);
	}

	env->ReleaseByteArrayElements(rgb_out, (jbyte*)rgb_bytes, JNI_COMMIT);
}

extern "C" JNIEXPORT void JNICALL Java_com_almalence_util_ImageConversion_addCornersRGBA8888(JNIEnv* env, jclass,
		jbyteArray rgb_out, jint outWidth, jint outHeight)
{
	unsigned char *rgb_bytes = (unsigned char *)env->GetByteArrayElements(rgb_out, 0);
	addRoundCornersRGBA8888(rgb_bytes, outWidth, outHeight);
	env->ReleaseByteArrayElements(rgb_out, (jbyte*)rgb_bytes, JNI_COMMIT);
}

extern "C" JNIEXPORT jintArray JNICALL Java_com_almalence_util_HeapUtil_getMemoryInfo(JNIEnv* env, jclass)
{
	FILE *f;
	char dummy[1024];
	int MbInfo[2];

	// the fields we want
	unsigned long curr_mem_used;
	unsigned long curr_mem_free;
	unsigned long curr_mem_buffers;
	unsigned long curr_mem_cached;

	// 'file' stat seems to give the most reliable results
	f = fopen ("/proc/meminfo", "r");
	if (f==NULL) return 0;
	fscanf(f, "%s %ld %s ", dummy, &curr_mem_used, dummy);
	fscanf(f, "%s %ld %s ", dummy, &curr_mem_free, dummy);
	fscanf(f, "%s %ld %s ", dummy, &curr_mem_buffers, dummy);
	fscanf(f, "%s %ld %s ", dummy, &curr_mem_cached, dummy);
	fclose(f);

	MbInfo[0] = curr_mem_used / 1024;
	MbInfo[1] = (curr_mem_free + curr_mem_cached) / 1024;

	//LOGI ("memory used: %ld  free: %ld", MbInfo[0], MbInfo[1]);

	jintArray memInfo = env->NewIntArray(2);
    if(memInfo)
        env->SetIntArrayRegion(memInfo, 0, 2, (jint*) MbInfo);

    return memInfo;
}
