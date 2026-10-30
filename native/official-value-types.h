/*
 * Copyright (C) 2005 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Selected EventHub value declarations for the pinned CP3 ABI.
#pragma once
#include <cstdint>
#include <cstddef>
#include <string>
#include <optional>
namespace android {
using nsecs_t=int64_t;
using RawDeviceId=int32_t;
struct InputDeviceIdentifier {
    inline InputDeviceIdentifier() :
            bus(0), vendor(0), product(0), version(0) {
    }

    // Information provided by the kernel.
    std::string name;
    std::string location;
    std::string uniqueId;
    uint16_t bus;
    uint16_t vendor;
    uint16_t product;
    uint16_t version;

    // A composite input device descriptor string that uniquely identifies the device
    // even across reboots or reconnections.  The value of this field is used by
    // upper layers of the input system to associate settings with individual devices.
    // It is hashed from whatever kernel provided information is available.
    // Ideally, the way this value is computed should not change between Android releases
    // because that would invalidate persistent settings that rely on it.
    std::string descriptor;

    // A value added to uniquely identify a device in the absence of a unique id. This
    // is intended to be a minimum way to distinguish from other active devices and may
    // reuse values that are not associated with an input anymore.
    uint16_t nonce;

    // The bluetooth address of the device, if known.
    std::optional<std::string> bluetoothAddress;

    /**
     * Return InputDeviceIdentifier.name that has been adjusted as follows:
     *     - all characters besides alphanumerics, dash,
     *       and underscore have been replaced with underscores.
     * This helps in situations where a file that matches the device name is needed,
     * while conforming to the filename limitations.
     */
    std::string getCanonicalName() const;

    bool operator==(const InputDeviceIdentifier&) const = default;
    bool operator!=(const InputDeviceIdentifier&) const = default;
};
struct RawEvent {
    // Time when the event happened
    nsecs_t when;
    // Time when the event was read by EventHub. Only populated for input events.
    // For other events (device added/removed/etc), this value is undefined and should not be read.
    nsecs_t readTime;
    RawDeviceId deviceId;
    int32_t type;
    int32_t code;
    int32_t value;
};
}
