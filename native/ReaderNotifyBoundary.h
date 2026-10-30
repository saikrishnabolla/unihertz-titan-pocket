#pragma once
#include "reader-boundary-hooks.h"
#include <atomic>
#include <memory>
#include <mutex>
namespace titan_runtime {
// Stack-only view of one borrowed original notification. A feature may forward
// early for cancellation ordering; fallback forwarding still runs exactly once.
class OriginalNotification final {
public:
 OriginalNotification(void* listener,const void* variant,void* reader,TitanCp3OriginalNotify forward) noexcept
  :listener_(listener),variant_(variant),reader_(reader),forward_(forward) {}
 ~OriginalNotification(){forward();}
 OriginalNotification(const OriginalNotification&)=delete;
 OriginalNotification& operator=(const OriginalNotification&)=delete;
 void forward() noexcept {
  if(forwarded_)return;
  forwarded_=true;
  if(!forward_){failed_=true;return;}
  forward_(listener_,variant_);
 }
 void* listener()const noexcept{return listener_;}
 const void* variant()const noexcept{return variant_;}
 void* reader()const noexcept{return reader_;}
 bool forwarded()const noexcept{return forwarded_;}
 bool failed()const noexcept{return failed_;}
private:
 void* const listener_;const void* const variant_;void* const reader_;
 const TitanCp3OriginalNotify forward_;
 bool forwarded_=false,failed_=false;
};
class ReaderNotifyBoundary final {
public:
 using Handler=bool(*)(void*,OriginalNotification&) noexcept;
 // Owner retains every object reachable by handler. One binding per process
 // lifetime prevents an old Reader address from authorizing a replacement.
 bool bind(void* reader,Handler handler,void* context,std::shared_ptr<const void> owner) {
  if(!reader||!handler||!context||!owner)return false;
  std::lock_guard lock(bindMutex_);
  if(binding_||disabled_.load(std::memory_order_acquire))return false;
  binding_=std::make_unique<const Binding>(Binding{reader,handler,context,std::move(owner)});
  published_.store(binding_.get(),std::memory_order_release);return true;
 }
 // Does not free the binding. In-flight calls retain valid process-lifetime
 // state; the handler must check its own generation before generated output.
 void disable()noexcept{disabled_.store(true,std::memory_order_release);}
 void notify(void* listener,const void* variant,void* reader,TitanCp3OriginalNotify forward)noexcept {
  OriginalNotification original(listener,variant,reader,forward);
  const auto* binding=published_.load(std::memory_order_acquire);
  if(!listener||!variant||!forward||!binding||binding->reader!=reader||disabled_.load(std::memory_order_acquire))return;
  if(!binding->handler(binding->context,original))disable();
 }
private:
 struct Binding {void* reader;Handler handler;void* context;std::shared_ptr<const void> owner;};
 std::mutex bindMutex_;
 std::unique_ptr<const Binding> binding_;
 std::atomic<const Binding*> published_{nullptr};
 std::atomic<bool> disabled_{false};
};
ReaderNotifyBoundary& readerNotifyBoundary()noexcept;
}
