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

#include "time_zone_win.h"

#include <chrono>

#include "cctz/civil_time.h"
#include "gtest/gtest.h"
#include "time_zone_info.h"

namespace chrono = std::chrono;

namespace cctz {
namespace {

time_point<seconds> FromUTC(year_t year, diff_t month, diff_t day, diff_t hour,
                            diff_t min, diff_t sec) {
  return FromUnixSeconds(civil_second(year, month, day, hour, min, sec) -
                         civil_second(1970, 1, 1, 0, 00, 00));
}

// This helper is a macro so that failed expectations show up with the
// correct line numbers.
#define ExpectTime(tp, tz, y, m, d, hh, mm, ss, off, isdst)       \
  do {                                                            \
    time_zone::absolute_lookup al = tz->BreakTime(tp);            \
    EXPECT_EQ(y, al.cs.year());                                   \
    EXPECT_EQ(m, al.cs.month());                                  \
    EXPECT_EQ(d, al.cs.day());                                    \
    EXPECT_EQ(hh, al.cs.hour());                                  \
    EXPECT_EQ(mm, al.cs.minute());                                \
    EXPECT_EQ(ss, al.cs.second());                                \
    EXPECT_EQ(off, al.offset);                                    \
    EXPECT_EQ(isdst, al.is_dst);                                  \
  } while (0)

// Asia/Kathmandu == Nepal Standard Time
const WinTimeZoneRegistryInfo kAsia_Kathmandu(
    {
        {-345, 0, -60, {0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0, 0, 0}},
    },
    0);

// Europe/Volgograd == Volgograd Standard Time
const WinTimeZoneRegistryInfo kEurope_Volgograd(
    {
        {-180, 0, -60, {0, 10, 0, 5, 3, 0, 0, 0}, {0, 3, 0, 5, 2, 0, 0, 0}},
        {-180, 0, -60, {0, 1, 6, 1, 0, 0, 0, 0}, {0, 3, 0, 5, 2, 0, 0, 0}},
        {-240, 0, -60, {0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0, 0, 0}},
        {-240, 0, -60, {0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0, 0, 0}},
        {-180, 0, -60, {0, 10, 0, 5, 2, 0, 0, 0}, {0, 1, 3, 1, 0, 0, 0, 0}},
        {-180, 0, -60, {0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0, 0, 0}},
        {-180, 0, -60, {0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0, 0, 0}},
        {-180, 0, -60, {0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0, 0, 0}},
        {-240, 0, 60, {0, 10, 0, 5, 2, 0, 0, 0}, {0, 1, 1, 1, 0, 0, 0, 0}},
        {-240, 0, -60, {0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0, 0, 0}},
        {-240, 0, -60, {0, 12, 0, 5, 2, 0, 0, 0}, {0, 1, 3, 1, 0, 0, 0, 0}},
        {-180, 0, -60, {0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0, 0, 0}},
        {-180, 0, -60, {0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0, 0, 0}},
    },
    2010);

// America/Denver == Mountain Standard Time
const WinTimeZoneRegistryInfo kAmerica_Denver(
    {
        {420, 0, -60, {0, 10, 0, 5, 2, 0, 0, 0}, {0, 4, 0, 1, 2, 0, 0, 0}},
        {420, 0, -60, {0, 11, 0, 1, 2, 0, 0, 0}, {0, 3, 0, 2, 2, 0, 0, 0}},
        {420, 0, -60, {0, 11, 0, 1, 2, 0, 0, 0}, {0, 3, 0, 2, 2, 0, 0, 0}},
    },
    2006);

// Australia/Adelaide == Cen. Australia Standard Time
const WinTimeZoneRegistryInfo kAustralia_Adelaide(
    {
        {-570, 0, -60, {0, 3, 0, 5, 3, 0, 0, 0}, {0, 10, 0, 5, 2, 0, 0, 0}},
        {-570, 0, -60, {0, 4, 0, 1, 3, 0, 0, 0}, {0, 10, 0, 1, 2, 0, 0, 0}},
        {-570, 0, -60, {0, 4, 0, 1, 3, 0, 0, 0}, {0, 10, 0, 1, 2, 0, 0, 0}},
    },
    2007);

// Africa/Abidjan == Greenwich Standard Time
const WinTimeZoneRegistryInfo kAfrica_Abidjan(
    {
        {0, 0, -60, {0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0, 0, 0}},
    },
    0);

// Europe/London == GMT Standard Time
const WinTimeZoneRegistryInfo kEurope_London(
    {
        {0, 0, -60, {0, 10, 0, 5, 2, 0, 0, 0}, {0, 3, 0, 5, 1, 0, 0, 0}},
    },
    0);

TEST(ToTzString, Africa_Abidjan) {
    EXPECT_EQ(
        "GMT0",
        ToTzString(kAfrica_Abidjan.entries.back()));
}

TEST(ToTzString, Europe_London) {
    EXPECT_EQ(
        "GMT0<GMT+01>-1,M3.5.0/1:00:00,M10.5.0/2:00:00",
        ToTzString(kEurope_London.entries.back()));
}

TEST(ToTzString, America_Denver) {
    EXPECT_EQ(
        "<GMT-07>7<GMT-06>6,M3.2.0/2:00:00,M11.1.0/2:00:00",
        ToTzString(kAmerica_Denver.entries.back()));
}

TEST(ToString, Asia_Kathmandu) {
    EXPECT_EQ(
        "<GMT+0545>-5:45",
        ToTzString(kAsia_Kathmandu.entries.back()));
}

TEST(ToTzString, Australia_Adelaide) {
    EXPECT_EQ(
        "<GMT+0930>-9:30<GMT+1030>-10:30,M10.1.0/2:00:00,M4.1.0/3:00:00",
        ToTzString(kAustralia_Adelaide.entries.back()));
}

// https://github.com/dotnet/runtime/issues/118915
TEST(CreateWinZoneInfoSource, Europe_Volgograd) {
    const auto source = CreateWinZoneInfoSource(kEurope_Volgograd);
    EXPECT_TRUE(!!source);
    auto tz = TimeZoneInfo::MakeFromSourceForTesting(source.get());
    EXPECT_TRUE(!!tz);

    ExpectTime(FromUTC(2019, 12, 31, 19, 0, 0), tz,
               2019, 12, 31, 23, 0, 0, 14400, false);
    ExpectTime(FromUTC(2019, 12, 31, 19, 30, 0), tz,
               2019, 12, 31, 23, 30, 0, 14400, false);
    ExpectTime(FromUTC(2019, 12, 31, 20, 0, 0), tz,
               2020, 1, 1, 1, 0, 0, 18000, true);
    ExpectTime(FromUTC(2019, 12, 31, 20, 30, 0), tz,
               2020, 1, 1, 1, 30, 0, 18000, true);
    ExpectTime(FromUTC(2019, 12, 31, 21, 0, 0), tz,
               2020, 1, 1, 2, 0, 0, 18000, true);
    ExpectTime(FromUTC(2019, 12, 31, 21, 30, 0), tz,
               2020, 1, 1, 2, 30, 0, 18000, true);
    ExpectTime(FromUTC(2020, 12, 31, 19, 0, 0), tz,
               2020, 12, 31, 23, 0, 0, 14400, false);
    ExpectTime(FromUTC(2020, 12, 31, 19, 30, 0), tz,
               2020, 12, 31, 23, 30, 0, 14400, false);
    ExpectTime(FromUTC(2020, 12, 31, 20, 0, 0), tz,
               2020, 12, 31, 23, 0, 0, 10800, false);
    ExpectTime(FromUTC(2020, 12, 31, 20, 30, 0), tz,
               2020, 12, 31, 23, 30, 0, 10800, false);
    ExpectTime(FromUTC(2020, 12, 31, 21, 0, 0), tz,
               2021, 1, 1, 0, 0, 0, 10800, false);
    ExpectTime(FromUTC(2020, 12, 31, 21, 30, 0), tz,
               2021, 1, 1, 0, 30, 0, 10800, false);
}


}  // namespace
}  // namespace cctz
