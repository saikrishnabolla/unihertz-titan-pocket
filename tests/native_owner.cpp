#include "NativeOwnerCore.h"
#include "ProcessMapping.h"
#include <map>
#include <cassert>
#include <atomic>
#include <functional>
#include <iostream>
#include <thread>
#include <sys/wait.h>
#include <unistd.h>
#include <csignal>
using namespace titan_native_owner;
struct FakeMemory:Memory {
 std::map<uintptr_t,unsigned char> bytes;
 template<class T>void put(uintptr_t address,T value){unsigned char data[sizeof(T)];std::memcpy(data,&value,sizeof(T));for(size_t i=0;i<sizeof(T);++i)bytes[address+i]=data[i];}
 bool read(uintptr_t address,void* out,size_t size)const noexcept override {auto p=static_cast<unsigned char*>(out);for(size_t i=0;i<size;++i){auto it=bytes.find(address+i);if(it==bytes.end())return false;p[i]=it->second;}return true;}
};
struct FakeStop:StopOperations {
 std::atomic<bool> done{false};std::atomic<int32_t> result{-110};std::atomic<int> calls{},maintains{};std::function<void()> onPrepare;
 int32_t prepare(Time,std::chrono::milliseconds)override {++calls;if(onPrepare)onPrepare();return result;}
 void maintenance(Time)override{++maintains;done=true;}
 bool safe()const override{return done;}
};
struct Fixture {
 const uintptr_t reader=0x200000,hub=0x300000,listener=0x400000,manager=0x500000;
 Layout layout{0x10000000,0x103d6b00,0x103d6c78,0x103d5f78,0x103d89a8,0x103d8d08,0x104040d4};
 std::shared_ptr<FakeMemory> memory=std::make_shared<FakeMemory>();
 Fixture(){
  memory->put(reader,layout.readerVtable);memory->put(reader+8,layout.readerContextVtable);memory->put(reader+16,reader);memory->put(reader+0x88,hub);memory->put(hub,layout.hubVtable);memory->put(reader+0xa0,listener);memory->put(listener,layout.listenerVtable);memory->put(manager,layout.managerVtable);memory->put(manager+0x28,reader);
  for(auto off:{0x2f0,0x2f8,0x300,0x308,0x318,0x320,0x328,0x330})memory->put(reader+off,uintptr_t{0});
  memory->put(reader+0x310,uint32_t{0x3f800000});memory->put(reader+0x338,uint32_t{0x3f800000});memory->put(reader+0x50,uintptr_t{0x600000});memory->put(0x600040,uint64_t{77});
 }
 bool attach(Core& c){return c.attach(reader,hub,layout.wake);}
};
int main(){int checks=0;auto check=[&](bool v){assert(v);++checks;};
 {Fixture f;Core c(f.layout,f.memory);check(f.attach(c));check(c.alive()&&c.startsEmpty());check(c.binding().listener==f.listener);check(c.binding().readerContext==f.reader+8);check(c.isThread(77)&&!c.isThread(78));check(!f.attach(c));check(c.readerStop(1,std::chrono::milliseconds(0))==0);check(!c.alive());}
 for(auto offset:{0,8,16,0x88,0xa0,0x2f0,0x2f8,0x300,0x308,0x318,0x320,0x328,0x330,0x310,0x338}){Fixture f;f.memory->put(f.reader+offset,uintptr_t{1});Core c(f.layout,f.memory);check(!f.attach(c));}
 {Fixture f;f.memory->put(f.listener,uintptr_t{f.layout.base+0x3d8938});Core c(f.layout,f.memory);check(!f.attach(c));}
 {Fixture f;Core c(f.layout,f.memory);check(!c.attach(f.reader,f.hub,f.layout.wake+4));}
 {Fixture f;Core c(f.layout,f.memory);check(f.attach(c));auto stop=std::make_shared<FakeStop>();check(c.attachEndpoint(stop));stop->onPrepare=[&]{check(c.alive());};check(c.managerStop(f.manager,1,std::chrono::milliseconds(0))==-110);check(c.alive());check(!c.attachEndpoint(std::make_shared<FakeStop>()));c.maintenance(2);check(stop->maintains==1&&c.alive());check(c.readerStop(3,std::chrono::milliseconds(0))==0);check(!c.alive());}
 {Fixture f;Core c(f.layout,f.memory);check(f.attach(c));auto stop=std::make_shared<FakeStop>();check(c.attachEndpoint(stop));check(c.managerStop(f.manager+8,1,std::chrono::milliseconds(0))==-22);check(stop->calls==0);f.memory->put(f.manager+0x28,uintptr_t{0x700000});check(c.managerStop(f.manager,1,std::chrono::milliseconds(0))==0);check(c.alive());}
 {Fixture f;Core c(f.layout,f.memory);check(f.attach(c));auto stop=std::make_shared<FakeStop>();check(c.attachEndpoint(stop));check(!c.attachEndpoint(std::make_shared<FakeStop>()));stop->done=true;check(c.attachEndpoint(std::make_shared<FakeStop>()));}
 {Fixture f;Core c(f.layout,f.memory);check(f.attach(c));auto stop=std::make_shared<FakeStop>();check(c.attachEndpoint(stop));stop->result=0;stop->onPrepare=[&]{check(c.alive());stop->done=true;};c.managerRetiring(f.manager,1);check(!c.alive());check(stop->calls==1);c.readerRetiring(f.reader,2);check(!c.alive());}
 {Fixture f;Core c(f.layout,f.memory);check(f.attach(c));c.readerRetiring(f.reader+8,1);check(c.alive());c.readerRetiring(f.reader,1);check(!c.alive());}
#if !__has_feature(thread_sanitizer)
 for(bool manager:{false,true}){auto child=fork();assert(child>=0);if(child==0){Fixture f;Core c(f.layout,f.memory);assert(f.attach(c));assert(c.attachEndpoint(std::make_shared<FakeStop>()));if(manager)c.managerRetiring(f.manager,1);else c.readerRetiring(f.reader,1);_exit(99);}int status{};waitpid(child,&status,0);check(WIFSIGNALED(status)&&WTERMSIG(status)==SIGABRT);}
#endif
 {Fixture f;Core c(f.layout,f.memory);check(f.attach(c));auto stop=std::make_shared<FakeStop>();check(c.attachEndpoint(stop));std::atomic<bool> entered{false};stop->result=0;stop->onPrepare=[&]{entered=true;while(!stop->done)std::this_thread::yield();};std::thread worker([&]{assert(c.readerStop(1,std::chrono::milliseconds(1000))==0);});while(!entered)std::this_thread::yield();check(c.alive());c.maintenance(2);worker.join();check(!c.alive());}
 {Fixture f;Core c(f.layout,f.memory);check(f.attach(c));auto stop=std::make_shared<FakeStop>();
  auto token=std::make_shared<std::atomic<bool>>(false);
  auto guarded=std::make_shared<QuiescedStopOperations>(stop,token);check(c.attachEndpoint(guarded));
  stop->done=true;stop->result=0;
  check(!guarded->safe());check(c.readerStop(1,std::chrono::milliseconds(0))==-110);
  check(c.alive());check(!c.attachEndpoint(std::make_shared<FakeStop>()));
  std::atomic<bool> entered{false};stop->onPrepare=[&]{entered=true;};
  std::thread worker([&]{assert(c.readerStop(2,std::chrono::milliseconds(1000))==0);});
  while(!entered)std::this_thread::yield();
  check(c.alive());check(!guarded->safe());
  // Only the Reader's completed native reset/CANCEL acknowledgement releases ownership.
  token->store(true,std::memory_order_release);worker.join();check(!c.alive());check(guarded->safe());
 }
 {auto stop=std::make_shared<FakeStop>();auto token=std::make_shared<std::atomic<bool>>(true);
  QuiescedStopOperations guarded(stop,token);check(!guarded.safe());
  stop->result=-38;check(guarded.prepare(1,std::chrono::milliseconds(0))==-38);
  stop->done=true;check(guarded.safe());
 }
 {Fixture f;Core c(f.layout,f.memory);check(std::strcmp(c.attachFailure(),"not-attempted")==0);f.memory->bytes.erase(f.reader);check(!f.attach(c));check(std::strcmp(c.attachFailure(),"reader-vtable-read")==0);}
 {Fixture f;Core c(f.layout,f.memory);f.memory->put(f.reader,uintptr_t{1});check(!f.attach(c));check(std::strcmp(c.attachFailure(),"reader-vtable-identity")==0);}
 {Fixture f;Core c(f.layout,f.memory);f.memory->put(f.reader+0x300,uintptr_t{1});check(!f.attach(c));check(std::strcmp(c.attachFailure(),"map-nonempty")==0);}
 {Fixture f;Core c(f.layout,f.memory);check(!c.attach(f.reader,f.hub,f.layout.wake+4));check(std::strcmp(c.attachFailure(),"wake-identity")==0);}
 {constexpr uintptr_t tagged=UINT64_C(0xb400000000002000);
  check(mappingAddress(tagged,true)==0x2000);check(mappingAddress(tagged,false)==tagged);
  check(readableMappingContains(tagged,8,0x2000,0x3000,true,true));
  check(!readableMappingContains(tagged,8,0x2000,0x3000,true,false));
  check(!readableMappingContains(tagged,8,0x2000,0x3000,false,true));
  check(!readableMappingContains(tagged,0x1001,0x2000,0x3000,true,true));
  check(readableMappingContains(tagged,0x1000,0x2000,0x3000,true,true));
  check(!readableMappingContains(tagged,1,0x2001,0x3000,true,true));
  check(!readableMappingContains(UINT64_C(0xb400000000000000),1,0,0x3000,true,true));
  check(!readableMappingContains(UINTPTR_MAX,2,0,UINTPTR_MAX,true,false));
  check(!readableMappingContains(tagged,0,0x2000,0x3000,true,true));
 }
 {Fixture f;auto m=std::make_shared<FakeMemory>();
  const uintptr_t tag=UINT64_C(0xb400000000000000),reader=f.reader|tag,hub=f.hub|tag,listener=f.listener|tag;
  m->put(reader,f.layout.readerVtable);m->put(reader+8,f.layout.readerContextVtable);m->put(reader+16,reader);
  m->put(reader+0x88,hub);m->put(hub,f.layout.hubVtable);m->put(reader+0xa0,listener);m->put(listener,f.layout.listenerVtable);
  for(auto off:{0x2f0,0x2f8,0x300,0x308,0x318,0x320,0x328,0x330})m->put(reader+off,uintptr_t{0});
  m->put(reader+0x310,uint32_t{0x3f800000});m->put(reader+0x338,uint32_t{0x3f800000});
  Core c(f.layout,m);check(c.attach(reader,hub,f.layout.wake));check(c.binding().reader==reader);
  check(c.binding().hub==hub);check(c.binding().listener==listener);check(c.binding().readerContext==reader+8);
  check(std::strcmp(c.attachFailure(),"none")==0);
 }
 std::cout<<checks<<" checks passed\n";
}
