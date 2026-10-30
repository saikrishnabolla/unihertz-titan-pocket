#include "OriginalViewportAdapter.h"
namespace titan_display {
std::optional<Binding> readOriginalViewport(const void* mapper,const void* context,
        const void* readerContext,const void* mapperVtable,const PolicyCalls& calls) noexcept {
    auto m=readMapper(mapper,context,readerContext,mapperVtable);
    if(!m||!calls.getPolicy||!calls.getViewport||!aligned(calls.readerVtable)||
        !aligned(calls.policyVtable)||field<const void*>(readerContext,0)!=calls.readerVtable)return {};
    if(field<GetPolicy>(calls.readerVtable,0x58)!=calls.getPolicy)return {};
    void *policy=calls.getPolicy(readerContext);
    if(!aligned(policy)||field<const void*>(policy,0)!=calls.policyVtable||
        field<GetViewport>(calls.policyVtable,0x60)!=calls.getViewport)return {};
    const auto viewport=calls.getViewport(policy,android::ui::LogicalDisplayId{m->associatedId});
    if(!viewport)return {};
    const auto& v=*viewport;
    auto result=validate(*m,ViewportFields{v.displayId.val(),static_cast<uint32_t>(v.orientation),
        v.logicalLeft,v.logicalTop,v.logicalRight,v.logicalBottom,v.isActive});
    // No input callbacks occur here. Recheck mapper metadata after the native query;
    // caller still owns the Reader lock throughout both observations.
    auto after=readMapper(mapper,context,readerContext,mapperVtable);
    if(!after||after->associatedId!=m->associatedId||after->left!=m->left||after->top!=m->top||
        after->right!=m->right||after->bottom!=m->bottom||after->inputRotation!=m->inputRotation)return {};
    return result;
}
}
