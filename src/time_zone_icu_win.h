// Copyright 2025 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   https://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.

#ifndef CCTZ_TIME_ZONE_ICU_WIN_H_
#define CCTZ_TIME_ZONE_ICU_WIN_H_

#include <memory>
#include <string>

#include "cctz/zone_info_source.h"

namespace cctz {

// Factory method to create an IcuZoneInfoSource for the given timezone.
// Returns nullptr if ICU is not available or the timezone is invalid.
std::unique_ptr<ZoneInfoSource> CreateIcuZoneInfoSource(const std::string& name);

// Get local timezone name using Windows ICU APIs
std::string win32_local_time_zone();

}  // namespace cctz

#endif  // CCTZ_TIME_ZONE_ICU_WIN_H_
