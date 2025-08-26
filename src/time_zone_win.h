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

#ifndef CCTZ_TIME_ZONE_WIN_H_
#define CCTZ_TIME_ZONE_WIN_H_

#include <cstdint>
#include <memory>
#include <vector>

#include "time_zone_if.h"

namespace cctz {

struct Win32SystemTime {
  Win32SystemTime()
      : year(0),
        month(0),
        day_of_week(0),
        day(0),
        hour(0),
        minute(0),
        second(0),
        milliseconds(0) {}
  Win32SystemTime(std::uint_fast16_t year_, std::uint_fast8_t month_,
                  std::uint_fast8_t day_of_week_, std::uint_fast8_t day_,
                  std::uint_fast8_t hour_, std::uint_fast8_t minute_,
                  std::uint_fast8_t second_, std::uint_fast16_t milliseconds_)
      : year(year_),
        month(month_),
        day_of_week(day_of_week_),
        day(day_),
        hour(hour_),
        minute(minute_),
        second(second_),
        milliseconds(milliseconds_) {}

  const std::uint_fast16_t year;
  const std::uint_fast8_t month;
  const std::uint_fast8_t day_of_week;
  const std::uint_fast8_t day;
  const std::uint_fast8_t hour;
  const std::uint_fast8_t minute;
  const std::uint_fast8_t second;
  const std::uint_fast16_t milliseconds;
};

struct Win32TimeZoneRegistryEntry {
  Win32TimeZoneRegistryEntry()
      : bias(0),
        standard_bias(0),
        daylight_bias(0),
        standard_date(),
        daylight_date() {}
  Win32TimeZoneRegistryEntry(std::int_fast32_t bias_,
                             std::int_fast32_t standard_bias_,
                             std::int_fast32_t daylight_bias_,
                             const Win32SystemTime& standard_date_,
                             const Win32SystemTime& daylight_date_)
      : bias(bias_),
        standard_bias(standard_bias_),
        daylight_bias(daylight_bias_),
        standard_date(standard_date_),
        daylight_date(daylight_date_) {}

  const std::int_fast32_t bias;
  const std::int_fast32_t standard_bias;
  const std::int_fast32_t daylight_bias;
  const Win32SystemTime standard_date;
  const Win32SystemTime daylight_date;
};

struct WinTimeZoneRegistryInfo {
  WinTimeZoneRegistryInfo() : entries(), first_year(0) {}
  WinTimeZoneRegistryInfo(std::vector<Win32TimeZoneRegistryEntry> entries_,
                          year_t first_year_)
      : entries(std::move(entries_)), first_year(first_year_) {}

  // This field is also used to indicate whether the object is valid or not.
  //  - Size of 0: Invalid object (e.g. failed to load from the registry).
  //  - Size of 1: No per-year override. `first_year` is ignored.
  //  - Size of N: Per-year override for N years with extrapolations with the
  //               first/last entry.
  std::vector<Win32TimeZoneRegistryEntry> entries;
  year_t first_year;
};

std::unique_ptr<TimeZoneIf> MakeTimeZoneFromWinRegistry(
    WinTimeZoneRegistryInfo info);

}  // namespace cctz

#endif  // CCTZ_TIME_ZONE_WIN_H_
