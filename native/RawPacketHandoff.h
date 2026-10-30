#pragma once
#include "RawSurfaceDecoder.h"
#include <memory>
namespace titan_surface {
// One gate per native mapper. All calls are serialized on Reader under its
// original mutex. Never destroy an owned gate before its physical stream ends.
class RawPacketHandoff final {
public:
 struct Observation {
  bool consumeOriginalSuppression=false;
  bool neutralBoundary=false;
  std::optional<Frame> frame;
 };
 RawPacketHandoff(titan_cp3_probe::Registration r,titan_cp3_probe::Callbacks calls,std::string descriptor)
  :calls_(calls),descriptor_(std::move(descriptor)){rebind(r);}
 bool rebind(titan_cp3_probe::Registration r) {
  ready_=false;decoder_.reset();resume_=true;quarantined_=quarantined_||owned_;
  if(mapper_ && mapper_!=r.mapper)return false;
  auto next=std::make_unique<RawSurfaceDecoder>(r,calls_,descriptor_);
  if(!next->authorized())return false;
  // Attachment may happen midway through a report. This first report cannot
  // establish lift, even when the first observed record happens to be SYN.
  next->reset(0);decoder_=std::move(next);registration_=r;mapper_=r.mapper;resume_=false;return true;
 }
 Observation observe(const titan_cp3_probe::Registration& current,const void* raw,size_t size) {
  Observation out{owned_,false,{}};ready_=false;
  if(resume_ && !rebind(current))return out;
  if(!decoder_)return out;
  out.frame=decoder_->consume(current,raw,size);
  if(!decoder_->authorized()){quarantined_=true;decoder_.reset();resume_=true;return out;}
  if(out.frame && !out.frame->valid)quarantined_=true;
  if(out.frame && out.frame->valid && out.frame->contacts.empty())ready_=out.neutralBoundary=true;
  return out;
 }
 // The raw record still belongs to the owner returned by observe(). These
 // methods affect only the NEXT record. Prime a new pipeline with the returned
 // empty frame after forwarding/suppressing that original neutral report.
 bool takeOwnership(){if(!ready_)return false;owned_=true;quarantined_=false;ready_=false;return true;}
 bool releaseOwnership(){if(!ready_)return false;owned_=false;quarantined_=false;ready_=false;return true;}
 // Invalidated ownership remains sticky until a verified neutral report. Its
 // caller must stop generated output, but must keep suppressing the raw stream.
 void quarantine(){quarantined_=true;ready_=false;}
 // When native inventory is unavailable, do not read it or use this raw record
 // as lift evidence. The next observe reconstructs and discards its first report.
 void unavailable(){decoder_.reset();resume_=true;ready_=false;quarantined_=quarantined_||owned_;}
 bool owned()const{return owned_;}
 bool quarantined()const{return quarantined_;}
 bool observing()const{return bool(decoder_);}
private:
 titan_cp3_probe::Callbacks calls_;
 const std::string descriptor_;
 const void* mapper_=nullptr;
 titan_cp3_probe::Registration registration_{};
 std::unique_ptr<RawSurfaceDecoder> decoder_;
 bool owned_=false,quarantined_=false,ready_=false,resume_=true;
};
}
