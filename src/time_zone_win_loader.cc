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

#include "time_zone_win_loader.h"

#if defined(_WIN32)

#if !defined(NOMINMAX)
#define NOMINMAX
#endif  // !defined(NOMINMAX)
#include <windows.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "icu_win.h"

namespace cctz {
namespace {

const wchar_t kRegistryPath[] =
    L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Time Zones";

// ARRAYSIZE(DYNAMIC_TIME_ZONE_INFORMATION::TimeZoneKeyName) == 128.
const size_t kWindowsTimeZoneNameMax = 128;

// The raw structure stored in the "TZI" value of the Windows registry.
// https://learn.microsoft.com/en-us/windows/win32/api/timezoneapi/ns-timezoneapi-time_zone_information#remarks
#pragma pack(push, 1)
struct REG_TZI_FORMAT {
  LONG Bias;
  LONG StandardBias;
  LONG DaylightBias;
  SYSTEMTIME StandardDate;
  SYSTEMTIME DaylightDate;
};
#pragma pack(pop)

using ScopedHKey =
    std::unique_ptr<std::remove_pointer<HKEY>::type, decltype(&::RegCloseKey)>;

ScopedHKey OpenRegistryKey(HKEY root, const wchar_t* sub_key) {
  HKEY hkey = nullptr;
  if (::RegOpenKeyExW(root, sub_key, 0, KEY_READ, &hkey) != ERROR_SUCCESS) {
    return ScopedHKey(nullptr, nullptr);
  }
  return ScopedHKey(hkey, ::RegCloseKey);
}

bool ReadDword(HKEY key, const wchar_t* value_name, DWORD* value) {
  DWORD size = sizeof(DWORD);
  DWORD temp_value;
  LSTATUS reg_result =
      ::RegGetValueW(key, nullptr, value_name, RRF_RT_REG_DWORD, nullptr,
                     reinterpret_cast<LPBYTE>(&temp_value), &size);
  if (reg_result != ERROR_SUCCESS || size != sizeof(DWORD)) {
    return false;
  }
  *value = temp_value;
  return true;
}

bool IsValidSystemTime(const SYSTEMTIME& st) {
  if (st.wYear == 0) {
    if (st.wMonth == 0) {
      return st.wDay == 0 && st.wDayOfWeek == 0 && st.wHour == 0 &&
             st.wMinute == 0 && st.wSecond == 0 && st.wMilliseconds == 0;
    }
    if (1 <= st.wMonth && st.wMonth <= 12) {
      // Special case for wYear == 0 and st.wMonth != 0:
      // http://learn.microsoft.com/en-us/windows/win32/api/timezoneapi/ns-timezoneapi-time_zone_information#members
      return 1 <= st.wDay && st.wDay <= 5 && 0 <= st.wDayOfWeek &&
             st.wDayOfWeek < 7 && 0 <= st.wHour && st.wHour < 24 &&
             0 <= st.wMinute && st.wMinute < 60 && 0 <= st.wSecond &&
             st.wSecond < 60 && 0 <= st.wMilliseconds &&
             st.wMilliseconds < 1000;
    }
    return false;
  }

  return 1601 <= st.wYear && st.wYear <= 30827 && 1 <= st.wMonth &&
         st.wMonth <= 12 && 1 <= st.wDay && st.wDay <= 31 &&
         0 <= st.wDayOfWeek && st.wDayOfWeek < 7 && 0 <= st.wHour &&
         st.wHour < 24 && 0 <= st.wMinute && st.wMinute < 60 &&
         0 <= st.wSecond && st.wSecond < 60 && 0 <= st.wMilliseconds &&
         st.wMilliseconds < 1000;
}

Win32SystemTime ToWin32SystemTime(const SYSTEMTIME& st) {
  return {st.wYear,
          static_cast<std::uint_fast8_t>(st.wMonth),
          static_cast<std::uint_fast8_t>(st.wDayOfWeek),
          static_cast<std::uint_fast8_t>(st.wDay),
          static_cast<std::uint_fast8_t>(st.wHour),
          static_cast<std::uint_fast8_t>(st.wMinute),
          static_cast<std::uint_fast8_t>(st.wSecond),
          st.wMilliseconds};
}

Win32TimeZoneRegistryEntry ReadTimeZoneInfo(HKEY key, const wchar_t* value_name,
                                            bool* succeeded) {
  REG_TZI_FORMAT format;
  DWORD size = sizeof(REG_TZI_FORMAT);
  LSTATUS reg_result =
      ::RegGetValueW(key, nullptr, value_name, RRF_RT_REG_BINARY, nullptr,
                     reinterpret_cast<LPBYTE>(&format), &size);
  if (reg_result != ERROR_SUCCESS || size != sizeof(REG_TZI_FORMAT)) {
    *succeeded = false;
    return {};
  }
  // Apply some limits to the Bias, StandardBias, and DaylightBias to avoid
  // accidental integer overflow.
  const LONG min_bias = -60 * 24 * 7;
  const LONG max_bias = 60 * 24 * 7;
  if (format.Bias < min_bias || max_bias < format.Bias ||
      format.StandardBias < min_bias || max_bias < format.StandardBias ||
      format.DaylightBias < min_bias || max_bias < format.DaylightBias) {
    *succeeded = false;
    return {};
  }
  if (!IsValidSystemTime(format.StandardDate) ||
      !IsValidSystemTime(format.DaylightDate)) {
    *succeeded = false;
    return {};
  }
  *succeeded = true;
  return {format.Bias, format.StandardBias, format.DaylightBias,
          ToWin32SystemTime(format.StandardDate),
          ToWin32SystemTime(format.DaylightDate)};
}

// Convert UTF-8 string to std::wstring (UTF-16)
std::wstring Utf8ToUtf16(const std::string& utf8str) {
  if (utf8str.size() > std::numeric_limits<int>::max()) {
    return std::wstring();
  }
  const char* utf8str_ptr = utf8str.data();
  const int utf8str_len = static_cast<int>(utf8str.size());
  int num_counts = 0;
  {
    // Fast-path for small strings.
    const int buffer_size = 32;
    wchar_t buffer[buffer_size];
    num_counts =
        ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8str_ptr,
                              utf8str_len, buffer, buffer_size);
    if (num_counts <= buffer_size) {
      return std::wstring(buffer, num_counts);
    }
    if (num_counts > std::numeric_limits<int>::max()) {
      return std::wstring();
    }
  }

  auto ustr = std::unique_ptr<wchar_t[]>(new wchar_t[num_counts]);
  const int written_counts =
      ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8str_ptr,
                            utf8str_len, ustr.get(), num_counts);
  if (num_counts != written_counts) {
    return std::wstring();
  }
  return std::wstring(ustr.get(), num_counts);
}

}  // namespace

WinTimeZoneRegistryInfo LoadWinTimeZoneRegistry(const std::string& name) {
  const std::wstring key_name =
      icu::ConvertToWindowsTimeZoneId(Utf8ToUtf16(name));
  if (key_name.empty()) {
    return {};
  }

  if (key_name.empty() || key_name.size() > kWindowsTimeZoneNameMax) {
    return {};
  }

  const std::wstring reg_tz_path =
      std::wstring(kRegistryPath) + L"\\" + key_name;

  ScopedHKey hkey_timezone =
      OpenRegistryKey(HKEY_LOCAL_MACHINE, reg_tz_path.c_str());
  if (!hkey_timezone) {
    return {};
  }
  std::vector<Win32TimeZoneRegistryEntry> timezone_list;
  DWORD first_year = 0;
  DWORD last_year = 0;

  ScopedHKey hkey_dynamic_years =
      OpenRegistryKey(hkey_timezone.get(), L"Dynamic DST");
  if (hkey_dynamic_years) {
    if (!ReadDword(hkey_dynamic_years.get(), L"FirstEntry", &first_year)) {
      return {};
    }
    if (!ReadDword(hkey_dynamic_years.get(), L"LastEntry", &last_year)) {
      return {};
    }
    if (first_year > last_year) {
      return {};
    }

    const size_t year_count = static_cast<size_t>(last_year - first_year + 1);
    timezone_list.reserve(year_count);
    for (DWORD year = first_year; year <= last_year; ++year) {
      const std::wstring key = std::to_wstring(year);
      bool succeeded = false;
      const auto entry =
          ReadTimeZoneInfo(hkey_dynamic_years.get(), key.c_str(), &succeeded);
      if (!succeeded) {
        return {};
      }
      timezone_list.push_back(entry);
    }
  }
  bool succeeded = false;
  const auto entry = ReadTimeZoneInfo(hkey_timezone.get(), L"TZI", &succeeded);
  if (!succeeded) {
    return {};
  }
  timezone_list.push_back(entry);
  timezone_list.shrink_to_fit();
  return {std::move(timezone_list), first_year};
}

}  // namespace cctz

#endif
