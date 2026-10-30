#pragma once
#include "official-value-types.h"
#include <limits>
#include <atomic>
#include <memory>
#include <vector>
#include <map>
#include <mutex>
#include <optional>
namespace titan_runtime {
inline bool inventoryIdPair(int32_t raw,int32_t logical)noexcept {
 return (raw>=0&&logical>=0)||(raw==-1&&logical==-1);
}
inline bool inventoryIds(int32_t raw,int32_t logical,uint32_t classes)noexcept {
 return inventoryIdPair(raw,logical)&&((raw>=0&&logical>=0)||(classes&536870912u));
}
struct Device {
 const void* context;
 const void* owner;
 int32_t raw;
 int32_t logical;
 uint32_t classes;
 std::string name;
 std::string descriptor;
 uint64_t lifetime;
};
struct Target {
 Device surface;
 int32_t keyboardRaw;
 uint64_t readerGeneration;
 uint64_t revision;
};
// Context hooks run under Android's Reader serialization. Cursor callbacks only
// read copied identity here; they must never query EventHub or take Reader locks.
class DeviceRegistry final {
public:
 bool start(void* reader, const void* hub) {
  std::lock_guard lock(mutex_);
  unpublish();
  if (!reader || !hub || reader_ || exhausted_ || generation_==UINT64_MAX) { poison();return false; }
  reader_=reader;hub_=hub;++generation_;complete_=false;return true;
 }
 bool add(void* reader,const void* hub,Device d) {
  std::lock_guard lock(mutex_);
  unpublish();
  if (!current(reader,hub) || !d.context || !d.owner || !inventoryIds(d.raw,d.logical,d.classes) || d.name.empty() || d.descriptor.empty()) { poison();return false; }
  for (const auto& [_,v]: devices_) if (v.raw==d.raw || v.context==d.context) { poison();return false; }
  if (lifetime_==UINT64_MAX || !advance()) {poison();return false;}
  d.lifetime=++lifetime_;devices_.emplace(d.context,std::move(d));unpublish();complete_=false;return true;
 }
 bool remove(void* reader,const void* context) {
  std::lock_guard lock(mutex_);
  unpublish();
  if (reader!=reader_ || !devices_.erase(context)) {poison();return false;}
  if (!advance()) return false;
  unpublish();complete_=false;return true;
 }
 // The caller must establish complete lifecycle coverage before sealing a loop.
 // A numeric revision alone never authorizes a partial startup snapshot.
 bool seal(void* reader,bool lifecycleCoverageProven) {
  std::lock_guard lock(mutex_);
  if (reader!=reader_ || poisoned_ || !lifecycleCoverageProven) {unpublish();complete_=false;return false;}
  complete_=true;
  auto t=targetLocked();
  if(!t){unpublish();return true;}
  const auto* current=published_.load(std::memory_order_relaxed);
  if(current && current->revision==t->revision && current->readerGeneration==t->readerGeneration)return true;
  // Incomplete publication does not change copied identity. Reuse the retained
  // immutable stamp for the same registry revision and Reader generation.
  if(!retained_.empty()) {
   const auto* last=retained_.back().get();
   if(last->revision==t->revision && last->readerGeneration==t->readerGeneration) {
    published_.store(last,std::memory_order_release);return true;
   }
  }
  if(retained_.size()>=512){poison();return false;}
  retained_.push_back(std::make_unique<const Target>(std::move(*t)));
  published_.store(retained_.back().get(),std::memory_order_release);return true;
 }
 std::optional<Target> target() const {std::lock_guard lock(mutex_);return targetLocked();}
 const Target* cursorSnapshot()const noexcept{return published_.load(std::memory_order_acquire);}
 bool currentSnapshot(const Target* p)const noexcept{return p && published_.load(std::memory_order_acquire)==p;}
 void incomplete(){std::lock_guard lock(mutex_);unpublish();complete_=false;}
 void reject(){std::lock_guard lock(mutex_);poison();}
 bool cursorTarget(int32_t logical) const {auto* t=cursorSnapshot();return t && t->surface.logical==logical && currentSnapshot(t);}
 bool matches(const Target& t) const {
  auto now=target();return now && now->readerGeneration==t.readerGeneration && now->revision==t.revision &&
   now->surface.context==t.surface.context && now->surface.lifetime==t.surface.lifetime && now->surface.descriptor==t.surface.descriptor;
 }
 bool stop(void* reader) {
  std::lock_guard lock(mutex_);
  if(reader!=reader_)return false;
  unpublish();complete_=false;devices_.clear();reader_=nullptr;hub_=nullptr;poisoned_=false;return advance();
 }
private:
 std::optional<Target> targetLocked() const {
  if (!reader_ || !complete_ || poisoned_)return {};
  const Device* surface=nullptr;const Device* keyboard=nullptr;
  for (const auto& [_,d]:devices_) {
   if (d.name=="mtk-pad") {if(surface)return {};surface=&d;}
   if (d.name=="aw9523-key") {if(keyboard)return {};keyboard=&d;}
  }
  constexpr uint32_t touchpad=65536, external=1073741824, virtualDevice=536870912;
  if(!surface || !keyboard || surface->raw<=0 || surface->logical<=0 || !(keyboard->classes&1) || !(surface->classes&touchpad) ||
     ((surface->classes|keyboard->classes)&(external|virtualDevice)))return {};
  // An aggregate may include fingerprint/key-only constituents, but no other
  // cursor/touch surface: a logical-ID cursor gate would also affect those.
  constexpr uint32_t pointerClasses=4|8|16|65536;
  for(const auto& [_,d]:devices_)
   if(d.context!=surface->context && d.logical==surface->logical && (d.classes&pointerClasses))return {};
  return Target{*surface,keyboard->raw,generation_,revision_};
 }
 bool current(void* reader,const void* hub)const{return reader_ && reader==reader_ && hub==hub_ && !poisoned_;}
 bool advance(){if(revision_==UINT64_MAX){exhausted_=true;poison();return false;}++revision_;return true;}
 void unpublish(){published_.store(nullptr,std::memory_order_release);}
 void poison(){unpublish();poisoned_=true;complete_=false;}
 static_assert(std::atomic<const Target*>::is_always_lock_free);
 std::atomic<const Target*> published_{nullptr};
 // Old snapshots remain valid for concurrent readers until this registry is destroyed.
 // Runtime owns the registry for process lifetime; bounded exhaustion blocks use.
 std::vector<std::unique_ptr<const Target>> retained_;
 mutable std::mutex mutex_;
 std::map<const void*,Device> devices_;
 void* reader_=nullptr;const void* hub_=nullptr;
 uint64_t generation_=0,revision_=0,lifetime_=0;
 bool complete_=false,poisoned_=false,exhausted_=false;
};
}
