#include <bit>
#include <jni.h>
#include <dlfcn.h>
#include "TitanSessionRegistry.h"
#include "DispatchEndpoint.h"
#include <chrono>
#ifdef __ANDROID__
#include <android/log.h>
#else
#include <cstdio>
#endif
#ifndef TITAN_READER_LIBRARY
#define TITAN_READER_LIBRARY "libinputflinger.so"
#endif
namespace {
unsigned int ready = 0;
void report(const char* phase, bool shared) noexcept {
    const auto snapshot = titan_surface_session_snapshot_v1();
#ifdef __ANDROID__
    __android_log_print(ANDROID_LOG_INFO, "TitanSurface", "phase=%s shared=%d snapshot=%llu",
                        phase, static_cast<int>(shared), snapshot);
#else
    std::fprintf(stderr, "TitanSurface phase=%s shared=%d snapshot=%llu\n",
                 phase, static_cast<int>(shared), snapshot);
#endif
}
bool sharesRegistry() noexcept {
    // NOLOAD observes an existing reader; it must never load a second copy.
    void* handle = dlopen(TITAN_READER_LIBRARY, RTLD_NOLOAD | RTLD_NOW);
    if (!handle) return false;
    void* symbol = dlsym(handle, "titan_surface_session_snapshot_v1");
    const bool same = symbol == reinterpret_cast<void*>(&titan_surface_session_snapshot_v1);
    const int closed = dlclose(handle);
    return same && closed == 0;
}
void block(JNIEnv*, jclass) { titan_surface_session_fail_closed_v1(); }
jlong stage(JNIEnv*, jclass) {
    static_assert(sizeof(jlong) == sizeof(unsigned long long));
    return std::bit_cast<jlong>(titan_surface_session_stage_v1());
}
void publish(JNIEnv*, jclass, jboolean allowed, jlong ticket) {
    const bool shared = __atomic_load_n(&ready, __ATOMIC_ACQUIRE) == 1;
    if (!shared) titan_surface_session_fail_closed_v1();
    else titan_surface_dispatch_commit_v1(allowed == JNI_TRUE,
            std::bit_cast<unsigned long long>(ticket),
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                    std::chrono::steady_clock::now().time_since_epoch()).count());
    report("publish", shared);
}
}
extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    __atomic_store_n(&ready, 0, __ATOMIC_RELEASE);
    titan_surface_session_publish_v1(false);
    const bool shared = sharesRegistry();
    report("load", shared);
    if (!shared) return JNI_ERR;
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;
    jclass helper = env->FindClass("com/android/server/input/NativeKeyboardSurfaceSession");
    if (!helper || env->ExceptionCheck()) return JNI_ERR;
    JNINativeMethod methods[] = {
        {const_cast<char*>("nativePublish"), const_cast<char*>("(ZJ)V"),
         reinterpret_cast<void*>(publish)},
        {const_cast<char*>("nativeStage"), const_cast<char*>("()J"), reinterpret_cast<void*>(stage)},
        {const_cast<char*>("nativeBlock"), const_cast<char*>("()V"), reinterpret_cast<void*>(block)},
    };
    const auto result = env->RegisterNatives(helper, methods, 3);
    env->DeleteLocalRef(helper);
    if (result != JNI_OK || env->ExceptionCheck()) return JNI_ERR;
    __atomic_store_n(&ready, 1, __ATOMIC_RELEASE);
    report("ready", true);
    return JNI_VERSION_1_6;
}
extern "C" JNIEXPORT void JNICALL JNI_OnUnload(JavaVM*, void*) {
    __atomic_store_n(&ready, 0, __ATOMIC_RELEASE);
    titan_surface_session_publish_v1(false);
    report("unload", false);
}
