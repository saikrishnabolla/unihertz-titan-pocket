#pragma once
#include "FrameSnapshotLedger.h"
#include "DisplayBinding.h"
#include "ReaderThreadIdentity.h"
#include <atomic>
#include <limits>
namespace titan_runtime {
// Construct on Reader. Record only copied results obtained under its original
// mutex; outside-lock native callbacks never call a locked original getter.
class ProductionSnapshots final {
public:
 ProductionSnapshots(titan_native::Binding binding,std::shared_ptr<const void> owner)
  :binding_(binding),owner_(std::move(owner)) {}
 bool recordLocked(const titan_display::Binding& display,int32_t meta,int64_t when,int64_t readTime,int64_t now,bool hooksVerified,bool targetVerified) {
  if(!thread_.isOwner()||!owner_||!hooksVerified||!targetVerified||disabled_.load()||
     when<0||readTime<when||now<readTime||generation_==UINT64_MAX)return reject();
  const auto checked=titan_display::validate(
   {display.associatedId,display.left,display.top,display.right,display.bottom,display.inputRotation},
   {display.displayId,display.displayRotation,display.logicalLeft,display.logicalTop,display.logicalRight,display.logicalBottom,true});
  if(!checked||*checked!=display)return reject();
  if(viewport_ && *viewport_!=display)return reject(); // Caller retires/rebinds after a viewport change.
  if(!viewport_)viewport_=display;
  titan_native::DisplaySnapshot s{};s.binding=binding_;s.viewportGeneration=1;
  s.readerStateGeneration=++generation_;s.capturedMetaState=meta;s.displayId=display.displayId;
  s.left=display.logicalLeft;s.top=display.logicalTop;s.right=display.logicalRight;s.bottom=display.logicalBottom;
  s.anchorX=s.left+(s.right-s.left)/2;s.anchorY=s.top+(s.bottom-s.top)/2;s.inverseRotation=display.inputRotation;
  s.observedAt=now;s.validUntil=deadline(now);s.readTime=readTime;s.anchoredTargetCopyHook=true;
  s.uncaptured=true;s.newInputAllowed=true;s.terminalOwnershipRetained=true;
  if(!ledger_.record(when,s))return reject();last_=s;return true;
 }
 bool capture(const titan_native::Binding& binding,titan_surface::Action action,int64_t when,
              const titan_native::DisplaySnapshot* retained,int64_t now,titan_native::DisplaySnapshot& out)const {
  if(!thread_.isOwner()||!owner_||binding!=binding_||when<0||now<when)return false;
  if(terminal(action)) {
   if(!retained||!viewport_||!last_||!terminalOwner_.load()||retained->binding!=binding_||
      retained->viewportGeneration!=1||!sameNativeViewport(*retained,*last_))return false;
   const auto queued=ledger_.lookup(when,binding_,1);
   if(action==titan_surface::Action::Up&&!queued)return false;
   const auto& captured=queued?*queued:*last_;
   out=*retained;out.readerStateGeneration=captured.readerStateGeneration;out.capturedMetaState=captured.capturedMetaState;
   out.observedAt=now;out.validUntil=deadline(now);out.readTime=queued?captured.readTime:now;
   out.newInputAllowed=false;out.terminalOwnershipRetained=true;return true;
  }
  if(disabled_.load()||retained)return false;
  auto value=ledger_.lookup(when,binding_,1);if(!value||value->validUntil<now)return false;
  out=*value;return true;
 }
 bool validate(const titan_native::Binding& binding,const titan_native::DisplaySnapshot& s,
               titan_surface::Action action,int64_t when,int64_t now)const {
  if(!thread_.isOwner()||!owner_||binding!=binding_||s.binding!=binding_||when<0||now<when||s.observedAt>now||s.validUntil<now)return false;
  if(terminal(action)) {
   if(!last_||!terminalOwner_.load())return false;
   const auto queued=ledger_.lookup(when,binding_,1);
   if(action==titan_surface::Action::Up&&!queued)return false;
   const auto& captured=queued?*queued:*last_;
   return s.viewportGeneration==1&&s.readerStateGeneration==captured.readerStateGeneration&&
    s.capturedMetaState==captured.capturedMetaState&&s.terminalOwnershipRetained&&!s.newInputAllowed&&
    s.readTime>=when&&s.readTime<=now&&(!queued||s.readTime==captured.readTime)&&sameNativeViewport(s,*last_);
  }
  if(disabled_.load())return false;
  auto original=ledger_.lookup(when,binding_,1);
  return original&&sameSnapshot(s,*original);
 }
 void invalidate()noexcept{disabled_.store(true,std::memory_order_release);}
 // Must follow dispatched/discarded batches, never precede their validation.
 void drained(){if(thread_.isOwner())ledger_.drained();else invalidate();}
 // Outer owner must quiesce original native calls before releasing its lifetime.
 void retireOwnership()noexcept{invalidate();terminalOwner_.store(false,std::memory_order_release);}
 bool healthy()const{return !disabled_.load();}
private:
 static bool terminal(titan_surface::Action a){return a==titan_surface::Action::Up||a==titan_surface::Action::Cancel;}
 static int64_t deadline(int64_t now){constexpr int64_t budget=500000000;return now>INT64_MAX-budget?INT64_MAX:now+budget;}
 static bool sameNativeViewport(const titan_native::DisplaySnapshot&a,const titan_native::DisplaySnapshot&b){
  return a.binding==b.binding&&a.viewportGeneration==b.viewportGeneration&&a.displayId==b.displayId&&a.left==b.left&&a.top==b.top&&a.right==b.right&&a.bottom==b.bottom&&a.anchorX==b.anchorX&&a.anchorY==b.anchorY&&a.inverseRotation==b.inverseRotation&&a.anchoredTargetCopyHook&&b.anchoredTargetCopyHook;
 }
 static bool sameSnapshot(const titan_native::DisplaySnapshot&a,const titan_native::DisplaySnapshot&b){return sameNativeViewport(a,b)&&a.readerStateGeneration==b.readerStateGeneration&&a.capturedMetaState==b.capturedMetaState&&a.observedAt==b.observedAt&&a.validUntil==b.validUntil&&a.readTime==b.readTime&&a.uncaptured==b.uncaptured&&a.newInputAllowed==b.newInputAllowed&&a.terminalOwnershipRetained==b.terminalOwnershipRetained;}
 bool reject(){invalidate();return false;}
 const titan_native::Binding binding_;
 const std::shared_ptr<const void> owner_;
 titan_surface::ReaderThreadIdentity thread_;
 FrameSnapshotLedger ledger_;
 std::optional<titan_display::Binding> viewport_;
 std::optional<titan_native::DisplaySnapshot> last_;
 uint64_t generation_=0;
 std::atomic<bool> disabled_{false},terminalOwner_{true};
};
}
