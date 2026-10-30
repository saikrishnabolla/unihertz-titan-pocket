#pragma once
#include "ProductionSink.h"
#include <array>
#include <optional>
#include <tuple>
namespace titan_runtime {
// Reader-thread storage. record runs under Reader mutex; lookup runs only after
// that same Reader releases it. Native callbacks consume copies, not live fields.
class FrameSnapshotLedger final {
public:
 bool record(int64_t eventTime,const titan_native::DisplaySnapshot& snapshot) {
  if(failed_ || eventTime<0 || !snapshot.readerStateGeneration || snapshot.readTime<eventTime)return reject();
  for(size_t i=0;i<size_;++i)if(records_[i]->when==eventTime) {
   // DOWN and first MOVE share a timestamp; both consume the same original stamp.
   const auto& a=records_[i]->snapshot;const auto& b=snapshot;
   const auto values=[](const auto& x){return std::tie(x.binding,x.viewportGeneration,x.readerStateGeneration,x.capturedMetaState,x.displayId,x.left,x.top,x.right,x.bottom,x.anchorX,x.anchorY,x.inverseRotation,x.observedAt,x.validUntil,x.readTime,x.anchoredTargetCopyHook,x.uncaptured,x.newInputAllowed,x.terminalOwnershipRetained);};
   return values(a)==values(b) ? true : reject();
  }
  if(size_==records_.size())return reject();
  records_[size_++]=Record{eventTime,snapshot};return true;
 }
 std::optional<titan_native::DisplaySnapshot> lookup(int64_t eventTime,
     const titan_native::Binding& binding,uint64_t viewportGeneration)const {
  if(failed_)return {};
  for(size_t i=0;i<size_;++i) {
   const auto& r=*records_[i];
   if(r.when==eventTime && r.snapshot.binding==binding && r.snapshot.viewportGeneration==viewportGeneration)return r.snapshot;
  }
  return {};
 }
 // Only after pending work is dispatched/discarded. Overflow never drops the
 // oldest stamp and then reinterprets an already queued event with newer state.
 void drained(){for(size_t i=0;i<size_;++i)records_[i].reset();size_=0;}
 void invalidate(){failed_=true;}
 bool healthy()const{return !failed_;}
private:
 bool reject(){failed_=true;return false;}
 struct Record {int64_t when;titan_native::DisplaySnapshot snapshot;};
 std::array<std::optional<Record>,256> records_{};
 size_t size_=0;bool failed_=false;
};
}
