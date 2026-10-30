#pragma once
#include "NativeMotionAdapter.h"
#include "DispatchCore.h"
#include <array>
#include <atomic>

namespace titan_native {
struct Binding {
    const void* reader;
    const void* mapper;
    const void* deviceOwner;
    uint64_t readerGeneration;
    uint64_t mapperGeneration;
    int32_t rawId;
    int32_t logicalDeviceId;
    bool operator==(const Binding&) const = default;
};
// These are logical display coordinates, not a guessed panel size. The runtime
// must prove its target-only PointerChoreographer copy hook is active: that hook
// bypasses the original pointer anchor transform for these already-anchored args.
struct DisplaySnapshot {
    Binding binding{};
    uint64_t viewportGeneration = 0;
    // Capture the original global meta state under Reader lock, then publish
    // this immutable generation to the outside-lock batch. No live getter here.
    uint64_t readerStateGeneration = 0;
    int32_t capturedMetaState = 0;
    int32_t displayId = -1;
    float left = 0, top = 0, right = 0, bottom = 0;
    float anchorX = 0, anchorY = 0;
    uint32_t inverseRotation = 0;
    int64_t observedAt = -1, validUntil = -1, readTime = -1;
    bool anchoredTargetCopyHook = false;
    bool uncaptured = false;
    bool newInputAllowed = false;
    bool terminalOwnershipRetained = false;
};
enum class PhysicalPhase { Down, End };
enum class Failure { MissingBinding, WrongThread, InvalidMotion, SnapshotRejected, NativeRejected, PhysicalRejected };
struct ProductionCalls {
    // For terminal events, retained points at the stream's original viewport.
    // Terminal capture must prove that old stream/listener ownership is retained,
    // even if lock, capture or viewport has changed since its DOWN.
    bool (*capture)(void*, const Binding&, titan_surface::Action, int64_t,
                    const DisplaySnapshot* retained, DisplaySnapshot&) noexcept;
    bool (*validate)(void*, const Binding&, const DisplaySnapshot&,
                     titan_surface::Action, int64_t) noexcept;
    bool (*now)(void*, int64_t&) noexcept;
    // Bind to the original Reader context methods, not a sidecar allocator.
    bool (*nextId)(void*, int32_t&) noexcept;
    void (*failed)(void*, Failure) noexcept;
    bool (*validatePhysical)(void*, const Binding&, void* listener,
                            const void* original, PhysicalPhase) noexcept;
    void (*forwardOriginal)(void*, void* listener, const void* original) noexcept;
};
class ProductionSink final : public titan_surface::Sink {
public:
    ProductionSink(NativeCalls native, void* listener, std::shared_ptr<const void> owner,
                   Binding binding, ProductionCalls calls, void* context);
    ProductionSink(const ProductionSink&) = delete;
    ProductionSink& operator=(const ProductionSink&) = delete;
    void generated(const titan_surface::Motion&) noexcept override;
    void physicalDown() noexcept override;
    void physicalEnd() noexcept override;
    bool healthy() const { return !failed_.load(); }
    bool active() const { return active_.load(); }
    // For the synchronous target-only PC hook. The borrowed original must point
    // to a complete, live 160-byte CP3 NotifyMotionArgs. This takes no Reader
    // locks and calls no runtime callbacks; the outer matcher must also check its
    // current lock-free target generation. No match survives emit/flush return.
    bool matchesGeneratedMotion(const void* original, size_t bytes) const noexcept;
    // Reader-only, outside Reader mutex. true means the exact borrowed original
    // was forwarded once; false means no original was forwarded and the caller
    // must keep its original notify path. Never retain original beyond this call.
    bool routePhysical(titan_surface::DispatchCore&, PhysicalPhase,
                       const void* original, int64_t when) noexcept;
private:
    static bool validateNative(const MotionInput&, const void*) noexcept;
    bool emit(const titan_surface::Motion&, const DisplaySnapshot&) noexcept;
    bool snapshot(const titan_surface::Motion&, DisplaySnapshot&) noexcept;
    bool structural(const DisplaySnapshot&, titan_surface::Action, int64_t, int64_t) const;
    bool sameViewport(const DisplaySnapshot&, const DisplaySnapshot&) const;
    void forward(PhysicalPhase) noexcept;
    void fail(Failure) noexcept;
    void cancelAfterFailure(int64_t) noexcept;
    struct ScopedOriginal { const void* original; PhysicalPhase phase; bool forwarded = false; };
    const Binding binding_;
    const ProductionCalls calls_;
    void* const context_;
    void* const listener_;
    const std::shared_ptr<const void> owner_;
    titan_surface::ReaderThreadIdentity readerThread_;
    NativeMotionAdapter adapter_;
    std::atomic<bool> failed_{false}, active_{false};
    bool emitting_ = false;
    mutable bool nativeValidated_ = false;
    ScopedOriginal* physical_ = nullptr;
    DisplaySnapshot stream_{};
    titan_surface::Motion last_{};
    const MotionInput* pending_ = nullptr;
    const DisplaySnapshot* pendingSnapshot_ = nullptr;
    titan_surface::Action pendingAction_ = titan_surface::Action::Cancel;
    const std::vector<android::TouchVideoFrame> noFrames_;
};
}
