#pragma once
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <memory>
#include <mutex>
#include <chrono>
#include <cstdlib>
#include <atomic>
#include <thread>
#include <algorithm>
namespace titan_native_owner {
using Time=int64_t;
struct Memory {virtual ~Memory()=default;virtual bool read(uintptr_t,void*,size_t)const noexcept=0;};
struct Layout {uintptr_t base,readerVtable,readerContextVtable,hubVtable,listenerVtable,managerVtable,wake;};
struct Binding {uintptr_t reader,hub,listener,readerContext;};
struct StopOperations {
 virtual ~StopOperations()=default;
 virtual int32_t prepare(Time,std::chrono::milliseconds)=0;
 virtual void maintenance(Time)=0;
 virtual bool safe()const=0;
};
class QuiescedStopOperations final:public StopOperations {
 const std::shared_ptr<StopOperations> core_;
 const std::shared_ptr<const std::atomic<bool>> nativeQuiesced_;
public:
 QuiescedStopOperations(std::shared_ptr<StopOperations> core,
     std::shared_ptr<const std::atomic<bool>> nativeQuiesced)
  :core_(std::move(core)),nativeQuiesced_(std::move(nativeQuiesced)){}
 int32_t prepare(Time when,std::chrono::milliseconds budget)override {
  budget=std::clamp(budget,std::chrono::milliseconds(0),std::chrono::milliseconds(2000));
  const auto deadline=std::chrono::steady_clock::now()+budget;
  const auto status=core_->prepare(when,budget);
  if(status!=0)return status;
  while(!safe()) {
   const auto now=std::chrono::steady_clock::now();
   if(now>=deadline)return -110;
   std::this_thread::sleep_until(std::min(deadline,now+std::chrono::milliseconds(1)));
  }
  return 0;
 }
 void maintenance(Time when)override{core_->maintenance(when);}
 bool safe()const override {
  return core_->safe()&&(!nativeQuiesced_||nativeQuiesced_->load(std::memory_order_acquire));
 }
};
class Core final {
public:
 Core(Layout l,std::shared_ptr<const Memory> m):layout_(l),memory_(std::move(m)){}
 bool attach(uintptr_t reader,uintptr_t hub,uintptr_t wake) {
  std::lock_guard guard(mutex_);
  auto fail=[&](const char* reason){attachFailure_=reason;return false;};
  if(attached_)return fail("already-attached");
  if(!memory_)return fail("memory-missing");
  if(!aligned(reader))return fail("reader-alignment");
  if(!aligned(hub))return fail("hub-alignment");
  if(wake!=layout_.wake)return fail("wake-identity");
  auto check=[&](uintptr_t address,uintptr_t expected,const char* unreadable,const char* mismatch){
   uintptr_t actual{};if(!read(address,actual))return fail(unreadable);
   return actual==expected?true:fail(mismatch);
  };
  uintptr_t listener{};
  if(!check(reader,layout_.readerVtable,"reader-vtable-read","reader-vtable-identity")||
     !check(reader+8,layout_.readerContextVtable,"context-vtable-read","context-vtable-identity")||
     !check(reader+16,reader,"context-owner-read","context-owner-identity")||
     !check(reader+0x88,hub,"hub-field-read","hub-field-identity")||
     !check(hub,layout_.hubVtable,"hub-vtable-read","hub-vtable-identity"))return false;
  if(!read(reader+0xa0,listener))return fail("listener-field-read");
  if(!aligned(listener))return fail("listener-alignment");
  if(!check(listener,layout_.listenerVtable,"listener-vtable-read","listener-vtable-identity"))return false;
  for(auto off:{0x2f0,0x2f8,0x300,0x308,0x318,0x320,0x328,0x330})
   if(!check(reader+off,0,"map-field-read","map-nonempty"))return false;
  uint32_t load1{},load2{};
  if(!read(reader+0x310,load1)||!read(reader+0x338,load2))return fail("map-load-read");
  if(load1!=0x3f800000||load2!=0x3f800000)return fail("map-load-identity");
  binding_={reader,hub,listener,reader+8};attached_=true;alive_=true;attachFailure_="none";return true;
 }
 const char* attachFailure()const {std::lock_guard guard(mutex_);return attachFailure_;}

 bool alive()const {std::lock_guard guard(mutex_);return alive_;}
 bool retired()const {std::lock_guard guard(mutex_);return retired_;}
 bool startsEmpty()const {std::lock_guard guard(mutex_);return attached_;}
 Binding binding()const {std::lock_guard guard(mutex_);return alive_?binding_:Binding{};}
 uintptr_t reader()const {std::lock_guard guard(mutex_);return binding_.reader;}
 bool isThread(uint64_t self)const {
  std::lock_guard guard(mutex_);if(!alive_)return false;uintptr_t thread{};uint64_t id{};
  return read(binding_.reader+0x50,thread)&&aligned(thread)&&read(thread+0x40,id)&&id==self;
 }
 bool attachEndpoint(std::shared_ptr<StopOperations> next) {
  std::lock_guard guard(mutex_);if(!alive_||closing_||!next||(stop_&&!stop_->safe()))return false;stop_=std::move(next);return true;
 }
 int32_t readerStop(Time when,std::chrono::milliseconds budget) {
  std::shared_ptr<StopOperations> stop;
  {std::lock_guard guard(mutex_);if(!attached_||retired_)return 0;closing_=true;stop=stop_;}
  int32_t status=0;if(stop&&!stop->safe())status=stop->prepare(when,budget);
  if(status==0&&stop&&!stop->safe())status=-16;
  // Ownership stays live through terminal CANCEL. Only a proven quiescent endpoint
  // permits the original stop body to invalidate Reader/thread/listener storage.
  if(status==0){std::lock_guard guard(mutex_);alive_=false;}
  return status;
 }
 int32_t managerStop(uintptr_t manager,Time when,std::chrono::milliseconds budget) {
  auto relation=managerRelation(manager);if(relation<0)return hasLiveEndpoint()?-22:0;if(relation==0)return 0;
  return readerStop(when,budget);
 }
 void readerRetiring(uintptr_t reader,Time when) {
  {std::lock_guard guard(mutex_);if(!attached_||reader!=binding_.reader)return;}
  retire(when);
 }
 void managerRetiring(uintptr_t manager,Time when) {
  auto relation=managerRelation(manager);if(relation==0)return;
  if(relation<0){if(hasLiveEndpoint())std::abort();return;}
  retire(when);
 }
 void maintenance(Time when) {
  std::shared_ptr<StopOperations> stop;
  {std::lock_guard guard(mutex_);if(!alive_)return;stop=stop_;}
  if(stop)stop->maintenance(when);
 }
private:
 template<class T>bool read(uintptr_t a,T& value)const {return memory_->read(a,&value,sizeof(value));}
 bool equal(uintptr_t a,uintptr_t expected)const {uintptr_t actual{};return read(a,actual)&&actual==expected;}
 static bool aligned(uintptr_t p){return p&&p%8==0&&p<=UINTPTR_MAX-0x400;}
 int managerRelation(uintptr_t manager)const {
  std::lock_guard guard(mutex_);if(!attached_)return 0;
  uintptr_t reader{};if(!aligned(manager)||!equal(manager,layout_.managerVtable)||!read(manager+0x28,reader)||!aligned(reader))return -1;
  // An unrelated valid original Manager is unbound to this generation.
  if(reader!=binding_.reader)return 0;
  return equal(reader,layout_.readerVtable)?1:-1;
 }
 bool hasLiveEndpoint()const {std::lock_guard guard(mutex_);return stop_&&!stop_->safe();}
 void retire(Time when) {
  if(readerStop(when,std::chrono::milliseconds(2000))!=0)std::abort();
  std::lock_guard guard(mutex_);retired_=true;
 }
 const Layout layout_;const std::shared_ptr<const Memory> memory_;
 mutable std::mutex mutex_;Binding binding_{};std::shared_ptr<StopOperations> stop_;
 bool attached_=false,alive_=false,closing_=false,retired_=false;
 const char* attachFailure_="not-attempted";
};
}
