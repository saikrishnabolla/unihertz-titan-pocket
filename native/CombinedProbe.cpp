#include "MapperPipeline.h"
#include "FrameSnapshotLedger.h"
#include "OriginalApiResolver.h"
#include "NativeMetadata.h"
bool stamp(titan_runtime::FrameSnapshotLedger& ledger,int64_t when,const titan_native::DisplaySnapshot& s){return ledger.record(when,s);}
bool originalContext(titan_runtime::DeviceRegistry& registry,const void* context,const titan_runtime::OriginalTypes& types){return titan_runtime::contextConstructed(registry,context,types);}
std::optional<titan_resolver::ResolvedApis> calls(){return titan_resolver::resolveOriginalApis();}

#include "InventoryRuntime.h"
#include "NativeReaderThread.h"
#include "ProductionSnapshots.h"
#include "RuntimePrerequisites.h"
bool inventoryBoundary(titan_inventory::InventoryRuntime& r,void* reader){return r.readerBoundary(reader);}
bool snapshotLive(titan_runtime::ProductionSnapshots& s){return s.healthy();}
std::shared_ptr<const titan_runtime::RuntimePrerequisites> prerequisites(){return titan_runtime::resolveRuntimePrerequisites();}
