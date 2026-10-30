#include "RuntimePrerequisites.h"
#include "NativeReaderOwner.h"
#include "DispatchEndpoint.h"
#include "final-hooks.h"
#include "TitanReaderLifecycle.h"
#include <cassert>
#include <cstring>
#include <iostream>
#include <thread>
#include <vector>
using namespace titan_runtime;
static unsigned checks=0;
#define CHECK(x) do{++checks;if(!(x)){std::cerr<<__LINE__<<": " #x "\n";std::abort();}}while(0)
template<size_t N>struct Bytes{alignas(8) unsigned char b[N]{};template<class T>void put(size_t o,T v){std::memcpy(b+o,&v,sizeof(v));}void* ptr(){return b;}};
struct FixtureDevice{Bytes<40> context;Bytes<32> owner;Bytes<0x500> mapper;int32_t raw,logical;uint32_t classes;const char* name;const char* descriptor;};
struct Event{int id,action,meta,device;int64_t when,read,down;};
struct Env{Bytes<0xb0> reader;Bytes<0x50> thread;Bytes<32> readerContext;Bytes<8> hub,mapperVtable,keyVtable,contextVtable,policyObject;Bytes<0x70> readerVtable,policyVtable;
 FixtureDevice pad{{},{},{},5,12,65536,"mtk-pad","pad-descriptor"},keyboard{{},{},{},0,0,1,"aw9523-key","key-descriptor"},touch{{},{},{},7,20,4,"touchscreen","touch-descriptor"},virtualKey{{},{},{},-1,-1,536870912u|1|2|32,"Virtual","virtual-descriptor"};
 const std::thread::id readerThread=std::this_thread::get_id();
 bool rejectAxis=false,pendingReset=false;int resetFlushed=0;
 std::shared_ptr<const std::atomic<bool>> quiesced;
 bool locked=false;int meta=65,id=100,wakes=0,forwards=0,pcMatches=0,nativeResets=0,endpointBindings=0;
 const void* expectedOriginal=nullptr;std::vector<Event> events;std::vector<int> order;Event pending{};std::array<unsigned char,160> copy{};
 std::shared_ptr<const RuntimePrerequisites> prerequisites;std::shared_ptr<int> lifetime=std::make_shared<int>(1);
 int64_t time=0;
 Env();int64_t nextTime(){timespec ts{};clock_gettime(CLOCK_MONOTONIC,&ts);auto now=int64_t(ts.tv_sec)*1000000000+ts.tv_nsec;return time=std::max(time+1,now);}
 FixtureDevice* device(int raw){for(auto* d:{&pad,&keyboard,&touch,&virtualKey})if(d->raw==raw)return d;return nullptr;}
 void initDevice(FixtureDevice& d){d.context.put(0,contextVtable.ptr());d.context.put(8,d.owner.ptr());d.context.put(16,readerContext.ptr());d.context.put(24,hub.ptr());d.context.put(32,d.raw);d.context.put(36,d.logical);d.owner.put(8,readerContext.ptr());d.owner.put(16,d.logical);d.mapper.put(0,d.raw==0?keyVtable.ptr():mapperVtable.ptr());d.mapper.put(8,d.context.ptr());}
 void lockedCall(auto&& call){assert(!locked);locked=true;call();locked=false;}
 bool raw(int type,int code,int value,int64_t when,void* mapper=nullptr,int rawId=5){TitanCp3RawEvent32 r{when,when+1,rawId,type,code,value};auto before=r;bool result=false;lockedCall([&]{result=titan_cp3_mapper_process_v1(mapper?mapper:pad.mapper.ptr(),&r);});CHECK(std::memcmp(&before,&r,sizeof(r))==0);return result;}
 void drain(){assert(!locked);titan_cp3_reader_drain_v1(reader.ptr());}
 bool neutral(){auto t=nextTime();bool a=raw(1,330,0,t);bool b=raw(1,325,0,t);bool c=raw(0,0,0,t);drain();return a&&b&&c;}
 void point(int x,int y){auto t=nextTime();for(auto [type,code,value]:std::vector<std::array<int,3>>{{3,57,1},{3,53,x},{3,54,y},{0,2,0},{1,330,1},{0,0,0}})CHECK(raw(type,code,value,t));drain();}
 void notify(int logical,int action,uint32_t source=0x1002){std::array<unsigned char,168> variant{};auto put=[&](size_t off,auto v){std::memcpy(variant.data()+off,&v,sizeof(v));};put(160,uint32_t(3));put(8,nextTime());put(16,logical);put(20,source);put(32,action);auto before=variant;expectedOriginal=variant.data();extern void originalForward(void*,const void*);titan_cp3_reader_notify_v1(this,variant.data(),reader.ptr(),originalForward);CHECK(variant==before);expectedOriginal=nullptr;}
 void publish(bool allowed){auto ticket=titan_surface_session_stage_v1();CHECK(titan_surface_dispatch_commit_v1(allowed,ticket,nextTime()));CHECK(bool(titan_surface_session_snapshot_v1()&1)==allowed);}
};
static Env* env;
static int32_t nextId(const void* p){assert(p==env->readerContext.ptr()&&!env->locked);return ++env->id;}
static int32_t meta(void* p){assert(p==env->readerContext.ptr()&&env->locked);return env->meta;}
static void* policy(const void* p){assert(p==env->readerContext.ptr()&&env->locked);return env->policyObject.ptr();}
static std::optional<android::DisplayViewport> viewport(void* p,android::ui::LogicalDisplayId id){assert(p==env->policyObject.ptr()&&env->locked&&id.val()==0);android::DisplayViewport v{};v.displayId=android::ui::LogicalDisplayId{0};v.orientation=static_cast<android::ui::Rotation>(0);v.logicalRight=480;v.logicalBottom=640;v.isActive=true;return v;}
static android::InputDeviceIdentifier identifier(const void* p,int32_t raw){assert(p==env->hub.ptr()&&env->locked);auto* d=env->device(raw);assert(d);android::InputDeviceIdentifier id{};id.name=d->name;id.descriptor=d->descriptor;return id;}
static uint32_t classes(const void* p,int32_t raw){assert(p==env->hub.ptr()&&env->locked);auto* d=env->device(raw);assert(d);return d->classes;}
static android::status_t axis(android::PointerCoords* c,int32_t a,float value){assert(std::this_thread::get_id()==env->readerThread&&!env->locked);if(env->rejectAxis)return -1;auto mask=uint64_t(1)<<(63-a);size_t index=__builtin_popcountll(c->bits&~(mask|(mask-1))),count=__builtin_popcountll(c->bits);if(!(c->bits&mask)){for(size_t i=count;i>index;--i)c->values[i]=c->values[i-1];c->bits|=mask;}c->values[index]=value;return 0;}
static void construct(void* p,int32_t id,int64_t when,int64_t read,int32_t device,uint32_t source,
 android::ui::LogicalDisplayId display,android::ftl::Flags<android::PolicyFlag> policyFlags,int32_t action,int32_t button,
 android::ftl::Flags<android::MotionFlag> flags,int32_t metaState,int32_t buttons,android::MotionClassification classification,
 uint32_t count,const android::PointerProperties*,const android::PointerCoords*,float xp,float yp,float xc,float yc,int64_t down,const std::vector<android::TouchVideoFrame>&){assert(std::this_thread::get_id()==env->readerThread&&!env->locked&&count==1);std::memset(p,0,160);auto put=[&](size_t off,auto v){std::memcpy((char*)p+off,&v,sizeof(v));};put(0,id);put(8,when);put(16,device);put(20,source);put(24,display.val());put(28,policyFlags.get());put(32,action);put(36,button);put(40,flags.get());put(44,metaState);put(48,buttons);put(52,uint8_t(classification));put(104,xp);put(108,yp);put(112,xc);put(116,yc);put(120,down);put(128,read);env->pending={id,action,metaState,device,when,read,down};}
static void destroyMotion(void*){assert(std::this_thread::get_id()==env->readerThread&&!env->locked);}
static void queueConstruct(void* p,void* listener){assert(std::this_thread::get_id()==env->readerThread&&!env->locked&&listener==env);std::memset(p,0,40);}
static void motionNotify(void*,const void* p){env->pendingReset=false;assert(std::this_thread::get_id()==env->readerThread&&!env->locked);std::memcpy(env->copy.data(),p,160);}
static void flush(void*){assert(std::this_thread::get_id()==env->readerThread&&!env->locked);if(env->pendingReset){CHECK(env->quiesced&&!env->quiesced->load());CHECK(titan_cp3_reader_stop_gate_v1(env->reader.ptr())!=0);++env->resetFlushed;env->order.push_back(88);return;}CHECK(titan_cp3_cursor_motion_v1(nullptr,env->copy.data()));++env->pcMatches;env->events.push_back(env->pending);env->order.push_back(env->pending.action);}
static void destroyQueue(void*){assert(std::this_thread::get_id()==env->readerThread&&!env->locked);}
static void resetConstruct(void* p,int32_t id,int64_t when,int32_t device){assert(std::this_thread::get_id()==env->readerThread&&!env->locked);CHECK(device==12&&id>0&&when>0);std::memcpy(p,&id,4);std::memcpy((char*)p+8,&when,8);std::memcpy((char*)p+16,&device,4);++env->nativeResets;}
static void resetNotify(void*,const void*){assert(std::this_thread::get_id()==env->readerThread&&!env->locked);env->pendingReset=true;}
void originalForward(void* listener,const void* p){assert(listener==env&&!env->locked&&p==env->expectedOriginal);++env->forwards;env->order.push_back(99);}
static void wake(void* hub)noexcept{assert(hub==env->hub.ptr());++env->wakes;}
namespace titan_installed {
std::shared_ptr<const InstalledHooks> resolveInstalledHooks()noexcept{return std::shared_ptr<const InstalledHooks>(new InstalledHooks(1,{nextId,meta,env->mapperVtable.ptr(),env->keyVtable.ptr()},{resetConstruct,resetNotify},env->lifetime));}
}
namespace titan_runtime {
std::shared_ptr<const RuntimePrerequisites> resolveRuntimePrerequisites()noexcept{return env->prerequisites;}
// Host environment substitute only. Actual /proc-map/native-stop owner has its
// own independent checks; this fixture executes actual Runtime.cpp wiring.
struct NativeReaderOwner::State{void* reader;bool live=true;std::thread::id thread=std::this_thread::get_id();std::shared_ptr<const RuntimePrerequisites> pre;std::shared_ptr<titan_surface::DispatchEndpoint> endpoint;std::shared_ptr<const std::atomic<bool>> quiesced;};
std::shared_ptr<NativeReaderOwner> NativeReaderOwner::create(void* r,void* hub,void(*)(void*)noexcept,std::shared_ptr<const RuntimePrerequisites> pre)noexcept{assert(r==env->reader.ptr()&&hub==env->hub.ptr());auto s=std::make_shared<State>();s->reader=r;s->pre=std::move(pre);return std::shared_ptr<NativeReaderOwner>(new NativeReaderOwner(s));}
void* NativeReaderOwner::reader()const noexcept{return state_->reader;}
void* NativeReaderOwner::listener()const noexcept{return env;}
void* NativeReaderOwner::readerContext()const noexcept{return env->readerContext.ptr();}
std::shared_ptr<const void> NativeReaderOwner::lifetime()const noexcept{return state_->pre;}
bool NativeReaderOwner::alive()const noexcept{return state_->live;}
bool NativeReaderOwner::startsEmpty()const noexcept{return true;}
bool NativeReaderOwner::isReaderThread()const noexcept{return state_->thread==std::this_thread::get_id();}
bool NativeReaderOwner::attachEndpoint(std::shared_ptr<titan_surface::DispatchEndpoint> endpoint,std::shared_ptr<const std::atomic<bool>> quiesced)noexcept{if(state_->endpoint&&(!state_->endpoint->core().retirementComplete()||(state_->quiesced&&!state_->quiesced->load())))return false;state_->endpoint=std::move(endpoint);state_->quiesced=std::move(quiesced);env->quiesced=state_->quiesced;++env->endpointBindings;return true;}
int32_t NativeReaderOwner::readerStopGate(int64_t,std::chrono::milliseconds)noexcept{if(state_->quiesced&&!state_->quiesced->load())return 1;state_->live=false;return 0;}
int32_t NativeReaderOwner::managerStopGate(void*,int64_t,std::chrono::milliseconds)noexcept{if(state_->quiesced&&!state_->quiesced->load())return 1;state_->live=false;return 0;}
void NativeReaderOwner::readerRetiring(void*,int64_t)noexcept{state_->live=false;}
void NativeReaderOwner::managerRetiring(void*,int64_t)noexcept{state_->live=false;}
void NativeReaderOwner::maintenance(int64_t when)noexcept{if(state_->endpoint)titan_surface::maintainDispatchEndpoint(state_->endpoint,when);}
}
Env::Env(){env=this;timespec ts{};clock_gettime(CLOCK_MONOTONIC,&ts);time=int64_t(ts.tv_sec)*1000000000+ts.tv_nsec;reader.put(0x50,thread.ptr());auto p=pthread_self();uint64_t tid;std::memcpy(&tid,&p,8);thread.put(0x40,tid);readerContext.put(0,readerVtable.ptr());readerContext.put(8,reader.ptr());readerVtable.put(0x58,&policy);policyVtable.put(0x60,&viewport);policyObject.put(0,policyVtable.ptr());for(auto* d:{&pad,&keyboard,&touch,&virtualKey})initDevice(*d);auto& m=pad.mapper;m.put<int32_t>(0x10c,0);m.put<uint8_t>(0x110,1);m.put<float>(0x114,0);m.put<float>(0x118,0);m.put<float>(0x11c,479);m.put<float>(0x120,639);m.put<uint32_t>(0x124,0);m.put<int32_t>(0x4e0,0);m.put<uint8_t>(0x4e4,1);
 auto pre=std::make_shared<RuntimePrerequisites>();pre->originals={{construct,destroyMotion,queueConstruct,motionNotify,flush,destroyQueue,axis},{policy,viewport,readerVtable.ptr(),policyVtable.ptr()},lifetime};pre->metadata={contextVtable.ptr(),readerVtable.ptr(),identifier,classes};pre->hooks=titan_installed::resolveInstalledHooks();prerequisites=pre;}
int main(){Env e;
 // Before any initialized runtime, exported notify still forwards exactly once.
 e.notify(999,0);CHECK(e.forwards==1&&e.events.empty());
 titan_cp3_reader_constructed_v1(e.reader.ptr(),e.hub.ptr(),wake);CHECK(titan_cp3_reader_ready_v1()&&e.wakes>=2);
 e.lockedCall([&]{for(auto* d:{&e.pad,&e.keyboard,&e.touch,&e.virtualKey})titan_cp3_context_constructed_v1(d->context.ptr());titan_cp3_mapper_constructed_v1(e.pad.mapper.ptr(),e.pad.context.ptr());});e.drain();
 CHECK(titan_cp3_cursor_controller_v1(nullptr,nullptr,12,0x100008));CHECK(!titan_cp3_cursor_controller_v1(nullptr,nullptr,999,0x100008));
 e.publish(true);CHECK(e.endpointBindings==0);CHECK(!e.neutral());CHECK(!e.neutral());CHECK(e.endpointBindings==1);
 e.point(100,100);e.point(120,130);e.point(130,145);CHECK(e.events.size()>=2&&e.events[0].action==0&&e.events[1].action==2&&e.events[0].device==12&&e.events[0].meta==65);CHECK(e.neutral());CHECK(e.events.back().action==1);CHECK(e.pcMatches==int(e.events.size()));
 size_t count=e.events.size();e.point(100,100);e.point(130,140);CHECK(e.events.size()>count);e.notify(20,0);CHECK(e.events.back().action==3&&e.order[e.order.size()-2]==3&&e.order.back()==99);e.notify(20,1);e.neutral();
 count=e.events.size();e.point(100,100);e.point(130,140);CHECK(e.events.size()>count);e.publish(false);e.drain();CHECK(e.events.back().action==3);count=e.events.size();e.neutral();e.point(100,100);e.point(130,140);CHECK(e.events.size()==count);e.neutral();e.publish(true);e.neutral();
 // Keyboard notification keeps original raw record and blocks synthetic input.
 auto t=e.nextTime();TitanCp3RawEvent32 key{t,t+1,0,1,30,1};e.lockedCall([&]{titan_cp3_keyboard_process_v1(e.keyboard.mapper.ptr(),&key);});e.drain();count=e.events.size();e.point(100,100);e.point(130,140);CHECK(e.events.size()==count);e.neutral();key.when=e.nextTime();key.readTime=key.when+1;key.value=0;e.lockedCall([&]{titan_cp3_keyboard_process_v1(e.keyboard.mapper.ptr(),&key);});e.drain();e.neutral();std::this_thread::sleep_for(std::chrono::milliseconds(400));e.point(100,100);e.point(130,140);CHECK(e.events.size()>count);e.neutral();
 count=e.events.size();CHECK(!e.raw(3,53,50,e.nextTime(),e.touch.mapper.ptr(),7));e.notify(999,0);CHECK(e.events.size()==count);CHECK(!titan_cp3_cursor_controller_v1(nullptr,nullptr,999,0x100008));
 auto oldBindings=e.endpointBindings;
 for(int cycle=0;cycle<40;++cycle){e.lockedCall([&]{titan_cp3_mapper_reset_v1(e.pad.mapper.ptr(),e.nextTime());});e.drain();CHECK(e.nativeResets==0);e.neutral();e.neutral();e.neutral();CHECK(e.endpointBindings==oldBindings+cycle+1);}
 count=e.events.size();e.point(100,100);e.point(130,140);CHECK(e.events.size()>count);
 const auto beforeForeign=e.events.size();std::thread javaPublisher([&]{e.publish(false);});javaPublisher.join();CHECK(e.events.size()==beforeForeign);e.drain();CHECK(e.events.back().action==3&&e.events.size()==beforeForeign+1);e.neutral();e.publish(true);e.neutral();
 count=e.events.size();e.point(100,100);e.point(130,140);CHECK(e.events.size()>count);e.neutral();
 CHECK(e.nativeResets==0);
 // Native MOVE and retained CANCEL both fail. Actual Runtime must flush one
 // native reset before publishing quiescence and releasing raw ownership.
 e.point(100,100);e.point(130,140);CHECK(e.quiesced&&!e.quiesced->load());const auto beforeFailure=e.events.size();e.rejectAxis=true;e.point(150,160);CHECK(e.nativeResets==1&&e.resetFlushed==1&&e.quiesced->load());CHECK(e.events.size()==beforeFailure);CHECK(e.neutral());CHECK(!e.neutral());CHECK(!titan_cp3_cursor_controller_v1(nullptr,nullptr,12,0x100008));e.notify(999,0);CHECK(e.nativeResets==1);
 std::cout<<checks<<" actual Runtime.cpp fixture checks passed; originals and NativeReaderOwner environment are host substitutes\n";
}
