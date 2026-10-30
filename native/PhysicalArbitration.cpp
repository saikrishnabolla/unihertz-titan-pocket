#include "PhysicalArbitration.h"
#include <cstring>
namespace titan_physical {
namespace {template<class T>T read(const void* p,unsigned off){T v;std::memcpy(&v,(const char*)p+off,sizeof(v));return v;}}
PhysicalArbitration::PhysicalArbitration(Calls calls,void* context,std::shared_ptr<const void> owner)
 :calls_(calls),context_(context),owner_(std::move(owner)) {}
int PhysicalArbitration::find(int32_t id)const noexcept{for(unsigned i=0;i<count_.load();++i)if(ids_[i]==id)return i;return -1;}
Decision PhysicalArbitration::fail(Failure f)noexcept{
 disabled_.store(true);lift_.store(true);Decision d;d.failure=f;d.invalidatePending=true;d.requireLift=true;return d;
}
void PhysicalArbitration::remove(unsigned index)noexcept{auto count=count_.load();for(unsigned i=index+1;i<count;++i)ids_[i-1]=ids_[i];ids_[count-1]=0;count_.store(count-1);}
Decision PhysicalArbitration::begin(const void* original,int64_t boundaryTime)noexcept{
 if(!reader_.isOwner())return fail(Failure::WrongThread);
 if(disabled_.load()){Decision d;d.invalidatePending=true;d.requireLift=true;return d;}
 if(!original||!calls_.classify||!context_||!owner_)return fail(Failure::Unconfigured);
 if(pendingToken_)return fail(Failure::NestedNotification);
 if(sequence_==UINT64_MAX)return fail(Failure::Exhausted);
 Decision d;d.token=++sequence_;d.when=boundaryTime;
 const auto tag=read<uint32_t>(original,160);
 if(tag>9)return fail(Failure::BadTag);
 removeMask_=0;
 if(tag==0){
  d.invalidatePending=true;
  unsigned removed=0;
  for(unsigned i=0;i<count_.load();++i)if(calls_.membership&&calls_.membership(context_,ids_[i])==Membership::ProvenAbsent){removeMask_|=uint16_t(1u<<i);++removed;}
  if(removed&&removed==count_.load())d.route=Route::PhysicalEnd;
 }else if(tag==6){
  d.when=read<int64_t>(original,8);d.logicalDeviceId=read<int32_t>(original,16);
  const int found=find(d.logicalDeviceId);
  if(found>=0){if(d.when<0)return fail(Failure::BadTime);removeMask_=uint16_t(1u<<found);if(count_.load()==1)d.route=Route::PhysicalEnd;}
 }else if(tag==3){
  Motion m{read<int64_t>(original,8),read<int32_t>(original,16),read<uint32_t>(original,20),read<int32_t>(original,32)};
  const auto type=calls_.classify(context_,m);
  if(type==PhysicalClass::Unavailable)return fail(Failure::InventoryUnavailable);
  if(type==PhysicalClass::PhysicalTouchscreen&&(m.source&0x1002u)==0x1002u){
   d.when=m.when;d.logicalDeviceId=m.device;
   if(m.when<0)return fail(Failure::BadTime);
   const uint32_t raw=uint32_t(m.action),action=raw&0xffu,index=(raw>>8)&0xffu;
   if(action>12||(raw&0xffff0000u)||(action!=5&&action!=6&&index)||index>=32)return fail(Failure::BadAction);
   const int found=find(m.device);
   if(action==0){
    if(found<0){const auto count=count_.load();if(count==16)return fail(Failure::Overflow);ids_[count]=m.device;count_.store(count+1);}
    d.route=Route::PhysicalDown;
   }else if(action==1||action==3){
    if(found>=0){removeMask_=uint16_t(1u<<found);if(count_.load()==1)d.route=Route::PhysicalEnd;}
   }else if((action==2||action==5||action==6)&&found<0)return fail(Failure::MissingDown);
  }
 }
 if(d.route==Route::PhysicalEnd&&d.when<0)return fail(Failure::BadTime);
 pendingToken_=d.token;return d;
}
bool PhysicalArbitration::afterOriginal(const Decision& d,bool originalForwarded,bool orderingSucceeded)noexcept{
 if(!reader_.isOwner()){fail(Failure::WrongThread);return false;}
 if(disabled_.load())return false;
 if(!originalForwarded||!orderingSucceeded||!d.token||d.token!=pendingToken_){fail(Failure::BadCompletion);return false;}
 // Descending order keeps removal-mask indices stable; no external callbacks.
 for(int i=15;i>=0;--i)if(removeMask_&(1u<<i))remove(unsigned(i));
 pendingToken_=0;removeMask_=0;return true;
}
}
