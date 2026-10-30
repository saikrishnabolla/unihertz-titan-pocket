#pragma once
#include "DispatchEndpoint.h"
#include "TitanReaderLifecycle.h"
#include <chrono>
#include <condition_variable>
#include <mutex>
namespace titan_surface {
enum class StopResult : int32_t { Ready=0, SameReader=-38, Busy=-16, TimedOut=-110 };
class StopCoordinator final {
public:
 explicit StopCoordinator(std::shared_ptr<DispatchEndpoint> endpoint):endpoint_(std::move(endpoint)) {}
 // Must be called BEFORE original InputReader::stop or InputManager::stop.
 // Every nonzero result forbids running the original stop body. In particular,
 // Manager's original body would otherwise stop Dispatcher despite Reader error.
 StopResult prepare(Time when,std::chrono::milliseconds budget) {
  if(!endpoint_)return StopResult::Ready;
  if(endpoint_->core().isReaderThread())return StopResult::SameReader;
  std::unique_lock serial(stopMutex_,std::try_to_lock);
  if(!serial.owns_lock())return StopResult::Busy;
  if(endpoint_->core().retirementComplete())return StopResult::Ready;
  retireDispatchEndpoint(endpoint_,when); // Blocks generation immediately; no foreign Sink call.
  if(endpoint_->core().retirementComplete())return StopResult::Ready;
  titan_cp3_reader_wake_v1();
  budget=std::clamp(budget,std::chrono::milliseconds(0),std::chrono::milliseconds(2000));
  const auto deadline=std::chrono::steady_clock::now()+budget;
  std::unique_lock wait(waitMutex_);
  while(!endpoint_->core().retirementComplete()) {
   auto now=std::chrono::steady_clock::now();if(now>=deadline)return StopResult::TimedOut;
   changed_.wait_until(wait,std::min(deadline,now+std::chrono::milliseconds(5)));
  }
  return StopResult::Ready;
 }
 // Optional notification at the existing outside-lock Reader maintenance boundary.
 // It changes no ordering: the actual endpoint wrapper owns CANCEL/finalization.
 void maintenance(Time when) {
  maintainDispatchEndpoint(endpoint_,when);
  if(endpoint_ && endpoint_->core().retirementComplete())changed_.notify_all();
 }
 bool destructionSafe()const {return !endpoint_ || endpoint_->core().retirementComplete();}
private:
 std::shared_ptr<DispatchEndpoint> endpoint_;
 std::mutex stopMutex_,waitMutex_;
 std::condition_variable changed_;
};
}
