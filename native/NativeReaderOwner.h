#pragma once
#include <memory>
#include <atomic>
#include <chrono>
#include <cstdint>
namespace titan_surface {class DispatchEndpoint;}
namespace titan_runtime {
struct RuntimePrerequisites;
class NativeReaderOwner final {
public:
 static std::shared_ptr<NativeReaderOwner> create(void* reader,void* hub,
     void(*wake)(void*) noexcept,std::shared_ptr<const RuntimePrerequisites>) noexcept;
 void* reader()const noexcept;
 void* listener()const noexcept;
 void* readerContext()const noexcept;
 std::shared_ptr<const void> lifetime()const noexcept;
 bool alive()const noexcept;
 bool startsEmpty()const noexcept;
 bool isReaderThread()const noexcept;
 bool attachEndpoint(std::shared_ptr<titan_surface::DispatchEndpoint>,
     std::shared_ptr<const std::atomic<bool>> nativeQuiesced={}) noexcept;
 int32_t readerStopGate(int64_t when,std::chrono::milliseconds budget) noexcept;
 int32_t managerStopGate(void* manager,int64_t when,std::chrono::milliseconds budget) noexcept;
 void readerRetiring(void* reader,int64_t when) noexcept;
 void managerRetiring(void* manager,int64_t when) noexcept;
 void maintenance(int64_t when) noexcept;
private:
 struct State;
 explicit NativeReaderOwner(std::shared_ptr<State> state):state_(std::move(state)){}
 const std::shared_ptr<State> state_;
};
}
