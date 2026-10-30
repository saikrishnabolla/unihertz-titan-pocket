#pragma once
#include "ContextAdapter.h"
#include "ReaderThreadIdentity.h"
#include "PhysicalArbitration.h"
#include <memory>
#include <thread>
#include <atomic>
#include <set>

namespace titan_inventory {
using titan_runtime::Device;
using titan_runtime::OriginalTypes;
// These are integration proofs, not values inferred from an empty local map.
// The loader must verify all final-v2 lifecycle hook bytes before Reader starts,
// and establish that its original constructor starts with no device contexts.
struct Coverage {
 bool hookBytesVerified;
 bool hooksActiveBeforeReaderConstruction;
 bool originalReaderStartsEmpty;
 bool complete()const {return hookBytesVerified && hooksActiveBeforeReaderConstruction && originalReaderStartsEmpty;}
};
using ReaderThreadCheck=bool(*)(const void* reader) noexcept;
struct NativeInputs {
 OriginalTypes metadata;
 const void* mapperAddressPoint;
 ReaderThreadCheck isReaderThread;
 std::shared_ptr<const void> apiLifetime;
 const void* keyboardMapperAddressPoint=nullptr;
};
struct Surface {
 const void* mapper;
 const void* context;
 const void* owner;
 const void* contextAddressPoint;
 const void* mapperAddressPoint;
 int32_t rawId;
 int32_t logicalId;
 int32_t keyboardRawId;
 uint64_t readerGeneration;
 uint64_t mapperGeneration;
 uint64_t inventoryRevision;
 std::string descriptor;
};
struct ContextIdentity {
 const void* context;const void* owner;int32_t rawId;int32_t logicalId;
 uint32_t classes;uint64_t readerGeneration;std::string name;std::string descriptor;
};
struct ReaderSnapshot {void* reader;const void* hub;uint64_t generation;bool complete;};
class InventoryRuntime final {
public:
 explicit InventoryRuntime(NativeInputs native):native_(std::move(native)) {}
 // Called from post-success original Reader construction. No thread identity is
 // captured here: construction runs on the service thread, not the input thread.
 bool readerConstructed(void* reader,const void* hub,Coverage coverage) {
  std::lock_guard lock(mutex_);
  if(reader_ || !reader || !hub || !native_.apiLifetime || !native_.isReaderThread ||
     !native_.metadata.identifier || !native_.metadata.classes ||
     !titan_runtime::aligned(native_.metadata.contextVtable) ||
     !titan_runtime::aligned(native_.metadata.readerContextVtable) ||
     !titan_runtime::aligned(native_.mapperAddressPoint) || !coverage.complete())return fail();
  if(readerGeneration_==UINT64_MAX || !devices_.start(reader,hub))return fail();
  ++readerGeneration_;reader_=reader;hub_=hub;coverage_=coverage;
  owner_.reset();contexts_.clear();mappers_.clear();retiredContexts_.clear();retiredMappers_.clear();boundarySeen_=false;failed_=false;return true;
 }
 // Original Reader serialization keeps these borrowed pointers live until the
 // callback returns. No native pointer is dereferenced on cursor threads.
 bool contextConstructed(const void* context) {
  std::lock_guard lock(mutex_);if(!acceptReader())return fail();
  auto observation=observe(context);if(!observation)return fail();
  if(contexts_.contains(context) || contexts_.size()>=512)return fail();
  retiredContexts_.erase(context);
  if(!devices_.add(reader_,hub_,observation->device))return fail();
  contexts_.emplace(context,std::move(*observation));boundarySeen_=false;return true;
 }
 bool contextRetiring(const void* context) {
  std::lock_guard lock(mutex_);if(!reader_)return false;
  if(!acceptReader())return fail();
  auto it=contexts_.find(context);if(it==contexts_.end())return retiredContexts_.contains(context)?true:fail();
  for(auto& [_,m]:mappers_)if(m.context==context) m.live=false;
  if(!devices_.remove(reader_,context))return fail();
  contexts_.erase(it);if(retiredContexts_.size()>=512)return fail();retiredContexts_.insert(context);boundarySeen_=false;return true;
 }
 bool mapperConstructed(void* mapper,const void* context) {
  std::lock_guard lock(mutex_);if(!acceptReader())return fail();
  auto c=contexts_.find(context);if(c==contexts_.end() || !mapper || mappers_.contains(mapper) || mappers_.size()>=512 ||
     !mapperFields(mapper,context))return fail();
  if(mapperGeneration_==UINT64_MAX)return fail();
  retiredMappers_.erase(mapper);
  mappers_.emplace(mapper,Mapper{context,++mapperGeneration_,true});return true;
 }
 bool mapperRetiring(void* mapper) {
  std::lock_guard lock(mutex_);if(!reader_)return false;
  if(!acceptReader())return fail();
  auto it=mappers_.find(mapper);if(it==mappers_.end())return retiredMappers_.contains(mapper)?true:fail();
  // Reconfiguration/reset invalidate a generation, but native retirement removes
  // it entirely so pointer reuse still requires a fresh successful constructor.
  mappers_.erase(it);incomplete();if(retiredMappers_.size()>=512)return fail();retiredMappers_.insert(mapper);return true;
 }
 bool mapperReconfigured(void* mapper) {
  std::lock_guard lock(mutex_);if(!acceptReader())return fail();
  auto m=mappers_.find(mapper);
  // Hooks may observe initialization before the successful constructor callback.
  // Never inspect or publish an unregistered mapper; false means no update.
  if(m==mappers_.end())return false;
  if(!m->second.live || !mapperFields(mapper,m->second.context))return fail();
  auto c=contexts_.find(m->second.context);if(c==contexts_.end())return fail();
  auto now=observe(m->second.context);
  if(!now || !sameDevice(now->device,c->second.device))return fail();
  if(mapperGeneration_==UINT64_MAX)return fail();
  m->second.generation=++mapperGeneration_;incomplete();return true;
 }
 bool mapperReset(void* mapper) {return mapperReconfigured(mapper);}
 // The post-loop hook is the first place publication may become visible. The
 // coverage proof covers all currently constructed native contexts; future
 // hotplug construction unpublishes the registry before that device can seal.
 bool readerBoundary(void* reader) {
  std::lock_guard lock(mutex_);
  if(reader!=reader_ || !acceptReader() || !coverage_.complete())return fail();
  if(!devices_.seal(reader_,true))return fail();boundarySeen_=true;return true;
 }
 std::optional<Surface> surface(void* mapper) {
  std::lock_guard lock(mutex_);if(!acceptReader() || !boundarySeen_)return {};
  auto m=mappers_.find(mapper);if(m==mappers_.end() || !m->second.live)return {};
  auto c=contexts_.find(m->second.context);if(c==contexts_.end() || !mapperFields(mapper,m->second.context)){fail();return {};}
  auto target=devices_.target();if(!target || target->surface.context!=m->second.context)return {};
  return Surface{mapper,m->second.context,c->second.device.owner,native_.metadata.contextVtable,
   native_.mapperAddressPoint,c->second.device.raw,c->second.device.logical,target->keyboardRaw,
   readerGeneration_,m->second.generation,target->revision,c->second.device.descriptor};
 }
 bool matches(const Surface& surface) {
  auto now=this->surface(const_cast<void*>(surface.mapper));
  return now && now->context==surface.context && now->owner==surface.owner && now->rawId==surface.rawId &&
   now->logicalId==surface.logicalId && now->keyboardRawId==surface.keyboardRawId &&
   now->readerGeneration==surface.readerGeneration && now->mapperGeneration==surface.mapperGeneration &&
   now->inventoryRevision==surface.inventoryRevision && now->descriptor==surface.descriptor;
 }
 // These queries inspect copies only, using the previously bound thread token.
 // They never call EventHub or dereference native Reader/thread/context storage.
 titan_physical::PhysicalClass classify(int32_t logicalId,uint32_t source) const {
  std::lock_guard lock(mutex_);
  using C=titan_physical::PhysicalClass;
  if(!copiedReader() || !boundarySeen_)return C::Unavailable;
  if(logicalId<0 || (source&0x1002u)!=0x1002u)return C::Other;
  bool physicalTouch=false;
  for(const auto& [_,observation]:contexts_) {
   const auto& d=observation.device;if(d.logical!=logicalId)continue;
   if(d.name=="mtk-pad" || (d.classes&536870912u))return C::Other;
   if(d.classes&4u)physicalTouch=true;
  }
  return physicalTouch?C::PhysicalTouchscreen:C::Other;
 }
 titan_physical::Membership membership(int32_t logicalId) const {
  std::lock_guard lock(mutex_);using M=titan_physical::Membership;
  if(!copiedReader() || !boundarySeen_ || logicalId<0)return M::Unknown;
  for(const auto& [_,o]:contexts_)if(o.device.logical==logicalId)return M::Present;
  return M::ProvenAbsent;
 }
 std::optional<ReaderSnapshot> readerSnapshot() const {
  std::lock_guard lock(mutex_);if(!copiedReader())return {};
  return ReaderSnapshot{reader_,hub_,readerGeneration_,boundarySeen_};
 }
 std::optional<titan_runtime::Target> targetSnapshot() const {
  std::lock_guard lock(mutex_);if(!copiedReader() || !boundarySeen_)return {};
  return devices_.target();
 }
 // This callback alone reads a native mapper prefix. The caller must retain the
 // complete original keyboard mapper under Reader serialization; its pinned
 // address point is distinct from TouchpadInputMapper's address point.
 std::optional<ContextIdentity> keyboardContext(const void* mapper) const {
  std::lock_guard lock(mutex_);
  if(!copiedReader() || !titan_runtime::aligned(native_.keyboardMapperAddressPoint) ||
     !titan_runtime::aligned(mapper) ||
     titan_runtime::field<const void*>(mapper,0)!=native_.keyboardMapperAddressPoint)return {};
  const auto* context=titan_runtime::field<const void*>(mapper,8);
  auto c=contexts_.find(context);if(c==contexts_.end())return {};
  const auto& d=c->second.device;
  if(!(d.classes&1u) || (d.classes&536870912u))return {};
  return ContextIdentity{d.context,d.owner,d.raw,d.logical,d.classes,readerGeneration_,d.name,d.descriptor};
 }
 // Teardown invalidates snapshots without querying native pointers or emitting
 // input. The outer lifetime owner must already have quiesced the endpoint.
 bool readerRetiring(void* reader) {
  std::lock_guard lock(mutex_);if(!reader_ || reader!=reader_)return false;
  devices_.stop(reader_);contexts_.clear();mappers_.clear();retiredContexts_.clear();retiredMappers_.clear();owner_.reset();reader_=nullptr;hub_=nullptr;
  boundarySeen_=false;failed_=false;return true;
 }
 const titan_runtime::Target* cursorSnapshot()const noexcept{return devices_.cursorSnapshot();}
 bool currentCursorSnapshot(const titan_runtime::Target*p)const noexcept{return devices_.currentSnapshot(p);}
 bool failed()const {std::lock_guard lock(mutex_);return failed_;}
private:
 struct Observation {const void* reader;const void* hub;Device device;};
 struct Mapper {const void* context;uint64_t generation;bool live;};
 std::optional<Observation> observe(const void* p)const {
  using namespace titan_runtime;
  if(!aligned(p) || field<const void*>(p,0)!=native_.metadata.contextVtable)return {};
  const void* owner=field<const void*>(p,8);const void* context=field<const void*>(p,16);const void* hub=field<const void*>(p,24);
  int32_t raw=field<int32_t>(p,32),logical=field<int32_t>(p,36);
  if(!aligned(owner)||!aligned(context)||!aligned(hub)||!inventoryIdPair(raw,logical) ||
     field<const void*>(context,0)!=native_.metadata.readerContextVtable ||
     field<const void*>(owner,8)!=context || field<int32_t>(owner,16)!=logical ||
     field<const void*>(context,8)!=reader_ || hub!=hub_)return {};
  auto id=native_.metadata.identifier(hub,raw);auto classes=native_.metadata.classes(hub,raw);
  if(!inventoryIds(raw,logical,classes))return {};
  return Observation{reader_,hub,Device{p,owner,raw,logical,classes,std::move(id.name),std::move(id.descriptor),0}};
 }
 static bool sameDevice(const Device&a,const Device&b){return a.context==b.context && a.owner==b.owner && a.raw==b.raw && a.logical==b.logical && a.classes==b.classes && a.name==b.name && a.descriptor==b.descriptor;}
 bool mapperFields(const void*p,const void*context)const {
  return titan_runtime::aligned(p) && titan_runtime::field<const void*>(p,0)==native_.mapperAddressPoint &&
   titan_runtime::field<const void*>(p,8)==context;
 }
 bool copiedReader() const {return reader_ && !failed_ && owner_ && owner_->isOwner();}
 void incomplete(){boundarySeen_=false;devices_.incomplete();}
 bool acceptReader() {
  if(!reader_ || failed_ || !native_.isReaderThread(reader_))return false;
  if(!owner_)owner_=std::make_unique<titan_surface::ReaderThreadIdentity>();
  return owner_->isOwner();
 }
 bool fail(){devices_.reject();failed_=true;boundarySeen_=false;return false;}
 NativeInputs native_;
 mutable std::mutex mutex_;
 titan_runtime::DeviceRegistry devices_;
 void* reader_=nullptr;const void* hub_=nullptr;
 Coverage coverage_{};
 uint64_t readerGeneration_=0,mapperGeneration_=0;
 bool boundarySeen_=false,failed_=false;
 std::unique_ptr<titan_surface::ReaderThreadIdentity> owner_;
 std::map<const void*,Observation> contexts_;
 std::map<void*,Mapper> mappers_;
 std::set<const void*> retiredContexts_;
 std::set<void*> retiredMappers_;
};
}
