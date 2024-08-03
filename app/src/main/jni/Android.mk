LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE    := frida_and_root_detection
LOCAL_SRC_FILES := frida_and_root_detection.c
include $(BUILD_SHARED_LIBRARY)