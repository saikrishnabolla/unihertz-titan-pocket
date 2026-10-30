#pragma once
#include <array>
#include <optional>
#include <string>
#include <vector>
#include "mapper/Macros.h"
namespace titan_cp3_protocol {
struct ErrorCode { int value() const{return -1;} };
struct Error {std::string message() const{return "unavailable";} ErrorCode code() const{return {};}};
struct Result { bool ok() const{return false;} std::vector<int32_t> value() const{return {};} Error error() const{return {};}};
struct InputDeviceContext { bool hasAbsoluteAxis(int) const{return false;} Result getMtSlotValues(int,int) const{return {};} std::optional<int32_t> getAbsoluteAxisValue(int) const{return {};} };
}
