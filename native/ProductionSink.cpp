#include "ProductionSink.h"
#include <cmath>
#include <limits>
#include <cstring>

namespace titan_native {
using titan_surface::Action;
using titan_surface::Motion;
ProductionSink::ProductionSink(NativeCalls native, void* listener,
        std::shared_ptr<const void> owner, Binding binding, ProductionCalls calls, void* context)
    : binding_(binding), calls_(calls), context_(context), listener_(listener),
      owner_(std::move(owner)), adapter_(native, listener, owner_, validateNative, this) {
    if (!readerThread_.isOwner() || !native.motionConstruct || !native.motionDestroy ||
        !native.queueConstruct || !native.queueNotifyMotion || !native.queueFlush ||
        !native.queueDestroy || !native.setAxisValue || !owner_ || !listener_ || !context_ ||
        !binding_.reader || !binding_.mapper ||
        !binding_.deviceOwner || !binding_.readerGeneration || !binding_.mapperGeneration ||
        binding_.rawId <= 0 || binding_.logicalDeviceId <= 0 || !calls_.capture ||
        !calls_.validate || !calls_.now || !calls_.nextId ||
        !calls_.failed || !calls_.validatePhysical || !calls_.forwardOriginal)
        fail(Failure::MissingBinding);
}
void ProductionSink::fail(Failure why) noexcept {
    if (!failed_.exchange(true) && calls_.failed && context_) calls_.failed(context_, why);
}
bool ProductionSink::sameViewport(const DisplaySnapshot& a, const DisplaySnapshot& b) const {
    return a.binding == b.binding && a.viewportGeneration == b.viewportGeneration &&
        a.displayId == b.displayId && a.left == b.left && a.top == b.top &&
        a.right == b.right && a.bottom == b.bottom && a.anchorX == b.anchorX &&
        a.anchorY == b.anchorY && a.inverseRotation == b.inverseRotation;
}
bool ProductionSink::structural(const DisplaySnapshot& s, Action action,
                                 int64_t when, int64_t now) const {
    const bool terminal = action == Action::Up || action == Action::Cancel;
    if (!(s.binding == binding_) || !s.viewportGeneration || !s.readerStateGeneration || s.displayId < 0 ||
        !s.anchoredTargetCopyHook || s.inverseRotation > 3 || now < 0 || when < 0 ||
        when > now || s.observedAt < 0 || s.observedAt > now || s.validUntil < now ||
        s.readTime < when || s.readTime > now) return false;
    for (float value : {s.left,s.top,s.right,s.bottom,s.anchorX,s.anchorY})
        if (!std::isfinite(value)) return false;
    if (!(s.left < s.right && s.top < s.bottom && s.anchorX >= s.left &&
          s.anchorX < s.right && s.anchorY >= s.top && s.anchorY < s.bottom)) return false;
    if (terminal) return s.terminalOwnershipRetained && active_.load() && sameViewport(s,stream_);
    return s.uncaptured && s.newInputAllowed;
}
bool ProductionSink::snapshot(const Motion& motion, DisplaySnapshot& out) noexcept {
    if (!calls_.capture || !calls_.now || !calls_.validate) return false;
    const bool terminal = motion.action == Action::Up || motion.action == Action::Cancel;
    int64_t now;
    if (!calls_.capture(context_, binding_, motion.action, motion.when,
                        terminal ? &stream_ : nullptr, out) ||
        !calls_.now(context_, now) || !structural(out,motion.action,motion.when,now) ||
        !calls_.validate(context_,binding_,out,motion.action,motion.when)) return false;
    if (active_.load() && !sameViewport(out,stream_)) return false;
    return true;
}
bool ProductionSink::validateNative(const MotionInput& input, const void* context) noexcept {
    const auto& self = *static_cast<const ProductionSink*>(context);
    if (&input != self.pending_ || !self.pendingSnapshot_ || !self.readerThread_.isOwner() ||
        (self.failed_.load() && self.pendingAction_!=Action::Cancel && self.pendingAction_!=Action::Up)) return false;
    int64_t now;
    const bool accepted=self.calls_.now(self.context_,now) &&
        self.structural(*self.pendingSnapshot_,self.pendingAction_,input.eventTime,now) &&
        self.calls_.validate(self.context_,self.binding_,*self.pendingSnapshot_,
                              self.pendingAction_,input.eventTime);
    self.nativeValidated_=accepted;
    return accepted;
}
bool ProductionSink::emit(const Motion& motion, const DisplaySnapshot& view) noexcept {
    float x=motion.x, y=motion.y;
    switch (view.inverseRotation) {
        case 1: { const float previous=x;x=y;y=-previous;break; }
        case 2: x=-x;y=-y;break;
        case 3: { const float previous=x;x=-y;y=previous;break; }
    }
    x+=view.anchorX;y+=view.anchorY;
    if (!std::isfinite(x) || !std::isfinite(y)) return false;
    const bool move=motion.action==Action::Move;
    const float dx=move ? -(motion.x-last_.x) : 0;
    const float dy=move ? -(motion.y-last_.y) : 0;
    if (!std::isfinite(dx) || !std::isfinite(dy)) return false;
    std::array<AxisValue,5> axes{{{0,x},{1,y},{2,1},{50,dx},{51,dy}}};
    std::array<PointerInput,1> pointers{{{{0,static_cast<android::ToolType>(1)},axes,false}}};
    int32_t id;
    if (!calls_.nextId(context_,id)) return false;
    const int32_t action=motion.action==Action::Down ? 0 : motion.action==Action::Move ? 2 :
                         motion.action==Action::Up ? 1 : 3;
    const uint32_t flags=0x48u | (motion.action==Action::Cancel ? 0x20u : 0u);
    MotionInput input{id,motion.when,view.readTime,binding_.logicalDeviceId,0x2002,
        android::ui::LogicalDisplayId{view.displayId},android::ftl::Flags<android::PolicyFlag>(1),
        action,0,android::ftl::Flags<android::MotionFlag>(flags),view.capturedMetaState,0,
        static_cast<android::MotionClassification>(3),pointers,1,1,view.anchorX,view.anchorY,
        motion.downTime,noFrames_};
    pending_=&input;pendingSnapshot_=&view;pendingAction_=motion.action;nativeValidated_=false;
    const bool accepted=adapter_.emit(input);
    nativeValidated_=false;pending_=nullptr;pendingSnapshot_=nullptr;
    if (accepted) {
        last_=motion;
        if (motion.action==Action::Down) {stream_=view;active_.store(true);}
        if (motion.action==Action::Up || motion.action==Action::Cancel) active_.store(false);
    }
    return accepted;
}
void ProductionSink::cancelAfterFailure(int64_t when) noexcept {
    if (!active_.load()) return;
    Motion cancellation=last_;
    int64_t now;
    if (!calls_.now || !calls_.now(context_,now) || now<last_.when) return;
    cancellation.action=Action::Cancel;
    cancellation.when=std::max(last_.when,std::min(when,now));
    DisplaySnapshot snapshot;
    if (this->snapshot(cancellation,snapshot)) emit(cancellation,snapshot);
}
void ProductionSink::generated(const Motion& motion) noexcept {
    if (!readerThread_.isOwner()) {fail(Failure::WrongThread);return;}
    if (emitting_) {fail(Failure::InvalidMotion);return;}
    if (failed_.load() && (!active_.load() ||
        (motion.action!=Action::Cancel && motion.action!=Action::Up))) return;
    emitting_=true;
    const bool down=motion.action==Action::Down;
    const bool known=motion.action==Action::Down || motion.action==Action::Move ||
        motion.action==Action::Up || motion.action==Action::Cancel;
    const bool terminal=motion.action==Action::Up || motion.action==Action::Cancel;
    const bool valid=known && (!terminal || (motion.x==last_.x && motion.y==last_.y)) && motion.when>=0 && motion.downTime>=0 && motion.downTime<=motion.when &&
        std::isfinite(motion.x) && std::isfinite(motion.y) &&
        ((down && !active_.load() && motion.downTime==motion.when && motion.x==0 && motion.y==0) ||
         (!down && active_.load() && motion.downTime==last_.downTime && motion.when>=last_.when));
    if (!valid) {cancelAfterFailure(motion.when);fail(Failure::InvalidMotion);emitting_=false;return;}
    DisplaySnapshot snapshot;
    if (!this->snapshot(motion,snapshot)) {
        cancelAfterFailure(motion.when);fail(Failure::SnapshotRejected);
    } else if (!emit(motion,snapshot)) {
        cancelAfterFailure(motion.when);fail(Failure::NativeRejected);
    }
    emitting_=false;
}
void ProductionSink::forward(PhysicalPhase phase) noexcept {
    if (!readerThread_.isOwner() || !physical_ || physical_->phase!=phase) {
        fail(Failure::PhysicalRejected);return;
    }
    if (physical_->forwarded) return;
    physical_->forwarded=true;
    calls_.forwardOriginal(context_,listener_,physical_->original);
}
void ProductionSink::physicalDown() noexcept {forward(PhysicalPhase::Down);}
void ProductionSink::physicalEnd() noexcept {forward(PhysicalPhase::End);}
bool ProductionSink::routePhysical(titan_surface::DispatchCore& core, PhysicalPhase phase,
                                   const void* original,int64_t when) noexcept {
    if (!readerThread_.isOwner() || !core.isReaderThread() || !core.usesSink(this) ||
        (phase!=PhysicalPhase::Down && phase!=PhysicalPhase::End) || when<0 ||
        !owner_ || !original || physical_ ||
        !calls_.validatePhysical || !calls_.forwardOriginal ||
        !calls_.validatePhysical(context_,binding_,listener_,original,phase)) return false;
    ScopedOriginal scope{original,phase};physical_=&scope;
    if (phase==PhysicalPhase::Down) core.physicalDown(when);
    else core.physicalEnd(when);
    // A closing/reentrant core must not swallow the real touchscreen record.
    if (!scope.forwarded) forward(phase);
    physical_=nullptr;
    return scope.forwarded;
}
}

namespace {
template<class T> T readScalar(const void* bytes,size_t offset) {
    T value;std::memcpy(&value,static_cast<const unsigned char*>(bytes)+offset,sizeof(value));return value;
}
}
namespace titan_native {
bool ProductionSink::matchesGeneratedMotion(const void* original,size_t bytes) const noexcept {
    if (!readerThread_.isOwner() || !original || bytes!=160 || !emitting_ ||
        !nativeValidated_ || !pending_ || !pendingSnapshot_) return false;
    const auto& p=*pending_;
    return readScalar<int32_t>(original,0)==p.id &&
        readScalar<int64_t>(original,8)==p.eventTime &&
        readScalar<int32_t>(original,16)==p.deviceId &&
        readScalar<uint32_t>(original,20)==p.source &&
        readScalar<int32_t>(original,24)==pendingSnapshot_->displayId &&
        readScalar<uint32_t>(original,28)==p.policyFlags.get() &&
        readScalar<int32_t>(original,32)==p.action &&
        readScalar<int32_t>(original,36)==p.actionButton &&
        readScalar<uint32_t>(original,40)==p.motionFlags.get() &&
        readScalar<int32_t>(original,44)==p.metaState &&
        readScalar<int32_t>(original,48)==p.buttonState &&
        readScalar<uint8_t>(original,52)==static_cast<uint8_t>(p.classification) &&
        readScalar<float>(original,104)==p.xPrecision &&
        readScalar<float>(original,108)==p.yPrecision &&
        readScalar<float>(original,112)==p.xCursorPosition &&
        readScalar<float>(original,116)==p.yCursorPosition &&
        readScalar<int64_t>(original,120)==p.downTime &&
        readScalar<int64_t>(original,128)==p.readTime;
}
}
