#include "ReaderNotifyBoundary.h"
namespace titan_runtime {
ReaderNotifyBoundary& readerNotifyBoundary()noexcept {
 [[clang::no_destroy]] static ReaderNotifyBoundary boundary;
 return boundary;
}
}
extern "C" void titan_cp3_reader_notify_v1(void* listener,const void* variant,void* reader,
 TitanCp3OriginalNotify forward)noexcept {
 titan_runtime::readerNotifyBoundary().notify(listener,variant,reader,forward);
}
