#include "InventoryRuntime.h"
#include "NativeReaderThread.h"
#include "scoped-binding-adapter.h"
#include <array>
#include <cassert>
#include <iostream>
#include <atomic>
using namespace titan_inventory;
template<size_t N>struct alignas(8) Bytes{std::array<std::byte,N> b{};void* p(){return b.data();}};
template<class T>void put(void*p,size_t off,T v){std::memcpy(static_cast<char*>(p)+off,&v,sizeof(v));}
std::atomic<int> getterCalls{0};
android::InputDeviceIdentifier identify(const void*,int32_t raw){++getterCalls;android::InputDeviceIdentifier d;d.name=raw==5?"mtk-pad":raw==0?"aw9523-key":raw==-1?"Virtual":raw==2?"fingerprint_key":"external-pad";d.descriptor="descriptor-"+std::to_string(raw);return d;}
uint32_t classes(const void*,int32_t raw){++getterCalls;return raw==-1?(536870912u|1|2|32):raw==5?65536:raw==11?(65536|1073741824):raw==12?4:raw==13?(4|1073741824):raw==14?(4|536870912):1;}
struct Fixture {
 Bytes<0x58> reader;Bytes<0x48> thread;Bytes<8> hub,cv,rv,mv,kv;Bytes<16> rc;Bytes<24> owner1,owner2,owner3;Bytes<40> c1,c2,c3;Bytes<16> m1,m2,km;
 NativeInputs inputs;std::unique_ptr<InventoryRuntime> runtime;
 Fixture(){
  put(reader.p(),0x50,thread.p());auto self=pthread_self();uint64_t bits;std::memcpy(&bits,&self,sizeof(bits));put(thread.p(),0x40,bits);
  put(rc.p(),0,rv.p());put(rc.p(),8,reader.p());context(c1.p(),owner1.p(),5,7);context(c2.p(),owner2.p(),0,0);context(c3.p(),owner3.p(),2,7);
  put(m1.p(),0,mv.p());put(m1.p(),8,c1.p());put(m2.p(),0,mv.p());put(m2.p(),8,c3.p());
  put(km.p(),0,kv.p());put(km.p(),8,c2.p());
  inputs={{cv.p(),rv.p(),identify,classes},mv.p(),nativeReaderThread,std::make_shared<const int>(1),kv.p()};runtime=std::make_unique<InventoryRuntime>(inputs);
 }
 void context(void*c,void*o,int raw,int logical){put(c,0,cv.p());put(c,8,o);put(c,16,rc.p());put(c,24,hub.p());put(c,32,raw);put(c,36,logical);put(o,8,rc.p());put(o,16,logical);}
 void construct(){bool okay=false;std::thread service([&]{okay=runtime->readerConstructed(reader.p(),hub.p(),{true,true,true});});service.join();assert(okay);}
 void discover(){assert(runtime->contextConstructed(c1.p()));assert(runtime->contextConstructed(c2.p()));assert(runtime->contextConstructed(c3.p()));assert(runtime->mapperConstructed(m1.p(),c1.p()));}
};
int main(){
 {Fixture f;f.construct();assert(!f.runtime->surface(f.m1.p()));f.discover();assert(!f.runtime->surface(f.m1.p()));assert(f.runtime->readerBoundary(f.reader.p()));auto s=f.runtime->surface(f.m1.p());assert(s && s->rawId==5 && s->keyboardRawId==0);assert(f.runtime->matches(*s));auto*cursor=f.runtime->cursorSnapshot();assert(cursor && f.runtime->currentCursorSnapshot(cursor));
  assert(f.runtime->mapperReconfigured(f.m1.p()));assert(!f.runtime->matches(*s));assert(f.runtime->membership(7)==titan_physical::Membership::Unknown);assert(!f.runtime->surface(f.m1.p()));assert(f.runtime->readerBoundary(f.reader.p()));auto n=f.runtime->surface(f.m1.p());assert(n && n->mapperGeneration!=s->mapperGeneration);assert(f.runtime->mapperReset(f.m1.p()));assert(!f.runtime->matches(*n));
  assert(f.runtime->mapperRetiring(f.m1.p()));assert(f.runtime->mapperRetiring(f.m1.p()));assert(!f.runtime->surface(f.m1.p()));assert(f.runtime->mapperConstructed(f.m1.p(),f.c1.p()));assert(f.runtime->readerBoundary(f.reader.p()));auto replacement=f.runtime->surface(f.m1.p());assert(replacement && !f.runtime->matches(*s));
  assert(f.runtime->contextRetiring(f.c1.p()));assert(f.runtime->contextRetiring(f.c1.p()));assert(!f.runtime->surface(f.m1.p()));assert(!f.runtime->currentCursorSnapshot(cursor));assert(cursor->surface.name=="mtk-pad");assert(f.runtime->mapperRetiring(f.m1.p()));
  assert(f.runtime->contextConstructed(f.c1.p()));assert(f.runtime->mapperConstructed(f.m1.p(),f.c1.p()));assert(!f.runtime->surface(f.m1.p()));assert(f.runtime->readerBoundary(f.reader.p()));assert(f.runtime->surface(f.m1.p()));assert(!f.runtime->matches(*replacement));
  assert(f.runtime->readerRetiring(f.reader.p()));assert(!f.runtime->surface(f.m1.p()));f.construct();f.discover();assert(f.runtime->readerBoundary(f.reader.p()));assert(!f.runtime->matches(*s));}
 {Fixture f;f.construct();f.discover();assert(f.runtime->readerBoundary(f.reader.p()));int before=getterCalls;bool okay=true;std::thread wrong([&]{okay=f.runtime->contextConstructed(f.c1.p());});wrong.join();assert(!okay && f.runtime->failed());assert(getterCalls==before);assert(!f.runtime->surface(f.m1.p()) && !f.runtime->cursorSnapshot());}
 {Fixture f;f.construct();f.discover();assert(!f.runtime->contextConstructed(f.c1.p()));assert(f.runtime->failed());assert(!f.runtime->readerBoundary(f.reader.p()));}
 {Fixture f;f.construct();f.discover();assert(!f.runtime->mapperConstructed(f.m1.p(),f.c1.p()));assert(f.runtime->failed());}
 {Fixture f;f.construct();int before=getterCalls;assert(!f.runtime->mapperReconfigured(f.m1.p()));assert(!f.runtime->mapperReset(f.m1.p()));assert(!f.runtime->failed());assert(getterCalls==before);f.discover();assert(f.runtime->readerBoundary(f.reader.p()));assert(f.runtime->surface(f.m1.p()));assert(!f.runtime->mapperReconfigured(f.m2.p()));assert(!f.runtime->failed());}
 {Fixture f;f.construct();f.discover();assert(f.runtime->readerBoundary(f.reader.p()));f.context(f.c3.p(),f.owner3.p(),11,9);assert(f.runtime->contextRetiring(f.c3.p()));assert(f.runtime->contextConstructed(f.c3.p()));assert(f.runtime->mapperConstructed(f.m2.p(),f.c3.p()));assert(f.runtime->readerBoundary(f.reader.p()));assert(!f.runtime->surface(f.m2.p()));assert(f.runtime->surface(f.m1.p()));}
 {Fixture f;assert(!f.runtime->readerConstructed(f.reader.p(),f.hub.p(),{true,false,true}));assert(!f.runtime->readerBoundary(f.reader.p()));}
 {Fixture f;f.construct();f.discover();assert(f.runtime->readerBoundary(f.reader.p()));put(f.m1.p(),8,f.c2.p());assert(!f.runtime->surface(f.m1.p()));assert(!f.runtime->mapperReconfigured(f.m1.p()));assert(f.runtime->failed());}
 {using C=titan_physical::PhysicalClass;using M=titan_physical::Membership;
  Fixture f;f.construct();assert(f.runtime->membership(7)==M::Unknown);assert(f.runtime->classify(7,0x1002)==C::Unavailable);
  f.discover();auto keyboard=f.runtime->keyboardContext(f.km.p());assert(keyboard && keyboard->rawId==0 && keyboard->context==f.c2.p());assert(!f.runtime->keyboardContext(f.m1.p()));
  put(f.km.p(),8,f.m2.p());assert(!f.runtime->keyboardContext(f.km.p()));put(f.km.p(),8,f.c2.p());
  assert(f.runtime->readerBoundary(f.reader.p()));assert(f.runtime->membership(7)==M::Present);assert(f.runtime->membership(999)==M::ProvenAbsent);assert(f.runtime->classify(7,0x1002)==C::Other);
  auto reader=f.runtime->readerSnapshot();assert(reader && reader->reader==f.reader.p() && reader->complete);assert(f.runtime->targetSnapshot());
  // Queries succeed with only copied state, even with no native thread pointer.
  int before=getterCalls;put(f.reader.p(),0x50,static_cast<void*>(nullptr));assert(f.runtime->membership(7)==M::Present);assert(f.runtime->classify(7,0x1002)==C::Other);assert(f.runtime->targetSnapshot());assert(getterCalls==before);put(f.reader.p(),0x50,f.thread.p());
  std::thread foreign([&]{assert(f.runtime->membership(7)==M::Unknown);assert(f.runtime->classify(7,0x1002)==C::Unavailable);assert(!f.runtime->readerSnapshot());assert(!f.runtime->targetSnapshot());assert(!f.runtime->keyboardContext(f.km.p()));});foreign.join();
  assert(f.runtime->contextRetiring(f.c3.p()));assert(f.runtime->membership(999)==M::Unknown);
  f.context(f.c3.p(),f.owner3.p(),12,42);assert(f.runtime->contextConstructed(f.c3.p()));assert(f.runtime->readerBoundary(f.reader.p()));assert(f.runtime->classify(42,0x1002)==C::PhysicalTouchscreen);assert(f.runtime->classify(42,0x2002)==C::Other);assert(f.runtime->classify(999,0x1002)==C::Other);
  assert(f.runtime->contextRetiring(f.c3.p()));f.context(f.c3.p(),f.owner3.p(),13,43);assert(f.runtime->contextConstructed(f.c3.p()));assert(f.runtime->readerBoundary(f.reader.p()));assert(f.runtime->classify(43,0x1002)==C::PhysicalTouchscreen);
  assert(f.runtime->contextRetiring(f.c3.p()));f.context(f.c3.p(),f.owner3.p(),14,44);assert(f.runtime->contextConstructed(f.c3.p()));assert(f.runtime->readerBoundary(f.reader.p()));assert(f.runtime->classify(44,0x1002)==C::Other);
  assert(f.runtime->mapperReset(f.m1.p()));assert(f.runtime->membership(44)==M::Unknown);assert(!f.runtime->cursorSnapshot());assert(!f.runtime->targetSnapshot());assert(f.runtime->readerBoundary(f.reader.p()));assert(f.runtime->membership(44)==M::Present);
  assert(f.runtime->readerRetiring(f.reader.p()));assert(f.runtime->membership(44)==M::Unknown);assert(f.runtime->classify(44,0x1002)==C::Unavailable);
 }
 {Fixture f;f.construct();f.discover();assert(f.runtime->readerBoundary(f.reader.p()));const auto* stable=f.runtime->cursorSnapshot();assert(stable);
  for(unsigned i=0;i<700;++i){assert(f.runtime->mapperReset(f.m1.p()));assert(!f.runtime->cursorSnapshot());assert(f.runtime->readerBoundary(f.reader.p()));assert(f.runtime->cursorSnapshot()==stable);}
  assert(f.runtime->contextRetiring(f.c3.p()));assert(f.runtime->readerBoundary(f.reader.p()));const auto* removed=f.runtime->cursorSnapshot();assert(removed && removed!=stable && removed->revision!=stable->revision);
  assert(f.runtime->contextConstructed(f.c3.p()));assert(f.runtime->readerBoundary(f.reader.p()));const auto* added=f.runtime->cursorSnapshot();assert(added && added!=removed && added->revision!=removed->revision);assert(stable->surface.name=="mtk-pad");
 }
 {using C=titan_physical::PhysicalClass;using M=titan_physical::Membership;
  Fixture f;f.context(f.c3.p(),f.owner3.p(),-1,-1);f.construct();f.discover();assert(f.runtime->readerBoundary(f.reader.p()));
  auto surface=f.runtime->surface(f.m1.p());assert(surface&&surface->rawId==5&&surface->keyboardRawId==0);
  auto keyboard=f.runtime->keyboardContext(f.km.p());assert(keyboard&&keyboard->rawId==0&&keyboard->logicalId==0);
  assert(f.runtime->membership(0)==M::Present);assert(f.runtime->membership(-1)==M::Unknown);
  assert(f.runtime->classify(-1,0x1002)==C::Other);assert(f.runtime->classify(0,0x1002)==C::Other);
  put(f.km.p(),8,f.c3.p());assert(!f.runtime->keyboardContext(f.km.p()));
  assert(f.runtime->contextRetiring(f.c3.p()));assert(f.runtime->readerBoundary(f.reader.p()));assert(f.runtime->surface(f.m1.p()));
 }
 {Fixture f;f.construct();f.context(f.c2.p(),f.owner2.p(),0,0);titan_runtime::DeviceRegistry registry;
  assert(registry.start(f.reader.p(),f.hub.p()));assert(titan_runtime::contextConstructed(registry,f.c2.p(),f.inputs.metadata));
  f.context(f.c3.p(),f.owner3.p(),-1,-1);assert(titan_runtime::contextConstructed(registry,f.c3.p(),f.inputs.metadata));
 }
 for(auto [raw,logical]:{std::pair{-2,-2},std::pair{-1,0},std::pair{0,-1},std::pair{5,-1}}){
  Fixture f;f.construct();f.context(f.c1.p(),f.owner1.p(),raw,logical);int before=getterCalls;
  assert(!f.runtime->contextConstructed(f.c1.p()));assert(f.runtime->failed());assert(getterCalls==before);
 }
 {using namespace titan_runtime;assert(inventoryIds(0,0,1));assert(inventoryIds(-1,-1,536870912u|1));
  assert(!inventoryIds(-1,-1,1));assert(!inventoryIds(-2,-2,536870912u));assert(!inventoryIds(-1,0,536870912u));
  Fixture f;DeviceRegistry r;assert(r.start(f.reader.p(),f.hub.p()));
  auto add=[&](const void*c,const void*o,int raw,int logical,uint32_t cl,const char*n){return r.add(f.reader.p(),f.hub.p(),{c,o,raw,logical,cl,n,"descriptor",0});};
  assert(add(f.c1.p(),f.owner1.p(),5,7,65536,"mtk-pad"));assert(add(f.c2.p(),f.owner2.p(),0,0,1,"aw9523-key"));
  assert(add(f.c3.p(),f.owner3.p(),-1,-1,536870912u|1|4,"Virtual"));assert(r.seal(f.reader.p(),true));
  assert(r.target()&&r.target()->surface.raw==5&&r.target()->keyboardRaw==0);
 }
 {using namespace titan_runtime;Fixture f;DeviceRegistry r;assert(r.start(f.reader.p(),f.hub.p()));
  assert(r.add(f.reader.p(),f.hub.p(),{f.c1.p(),f.owner1.p(),-1,-1,536870912u|65536,"mtk-pad","descriptor",0}));
  assert(r.add(f.reader.p(),f.hub.p(),{f.c2.p(),f.owner2.p(),0,0,1,"aw9523-key","descriptor",0}));
  assert(r.seal(f.reader.p(),true));assert(!r.target());
 }
 {android::RawEvent event{1,2,0,1,30,1};
  assert(titan_cp3_probe::rawEvent(&event,sizeof(event),0));
  assert(!titan_cp3_probe::rawEvent(&event,sizeof(event),1));
  assert(!titan_cp3_probe::rawEvent(&event,sizeof(event),-1));
  event.deviceId=-1;assert(!titan_cp3_probe::rawEvent(&event,sizeof(event),-1));
  event.deviceId=0;event.type=0x10000000;assert(!titan_cp3_probe::rawEvent(&event,sizeof(event),0));
  event.type=1;assert(!titan_cp3_probe::rawEvent(&event,sizeof(event)-1,0));
 }
 {Fixture f;f.inputs.metadata.classes=[](const void*,int32_t)->uint32_t{return 1;};
  f.runtime=std::make_unique<InventoryRuntime>(f.inputs);f.context(f.c3.p(),f.owner3.p(),-1,-1);f.construct();
  assert(!f.runtime->contextConstructed(f.c3.p()));assert(f.runtime->failed());
 }
 std::cout<<"Inventory lifecycle, thread binding, stale generations, duplicate rejection and external-device preservation passed\n";
}
