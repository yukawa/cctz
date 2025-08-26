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

#include "icu_win.h"

#if defined(_WIN32)

#if !defined(NOMINMAX)
#define NOMINMAX
#endif  // !defined(NOMINMAX)
#include <windows.h>

#include <atomic>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace cctz {
namespace icu {
namespace {

// ARRAYSIZE(DYNAMIC_TIME_ZONE_INFORMATION::TimeZoneKeyName) == 128.
const std::int32_t kWindowsTimeZoneNameMax = 128;

// UChar is defined as char16_t in ICU by default, but it is also safe to assume
// wchar_t and char16_t are equivalent on Windows.
using UChar = wchar_t;

enum UErrorCode : std::int32_t {
  U_ZERO_ERROR = 0,
  U_BUFFER_OVERFLOW_ERROR = 15,
};

bool U_SUCCESS(UErrorCode error) { return error <= U_ZERO_ERROR; }

// ICU function signatures
using ucal_getHostTimeZone_func = std::int32_t(__cdecl*)(
    UChar* result, std::int32_t result_capacity, UErrorCode* status);
using ucal_getTimeZoneIDForWindowsID_func = std::int32_t(__cdecl*)(
    const UChar* winid, std::int32_t len, const char* region, UChar* id,
    std::int32_t id_capacity, UErrorCode* status);
using ucal_getWindowsTimeZoneID_func =
    std::int32_t(__cdecl*)(const UChar* id, std::int32_t len, UChar* winid,
                           std::int32_t winid_capacity, UErrorCode* status);

std::atomic<bool> g_unavailable;
std::atomic<ucal_getHostTimeZone_func> g_ucal_getHostTimeZone;
std::atomic<ucal_getTimeZoneIDForWindowsID_func>
    g_ucal_getTimeZoneIDForWindowsID;
std::atomic<ucal_getWindowsTimeZoneID_func> g_ucal_getWindowsTimeZoneID;

struct IcuFunctions {
  const bool available;
  const ucal_getHostTimeZone_func ucal_getHostTimeZone;
  const ucal_getTimeZoneIDForWindowsID_func ucal_getTimeZoneIDForWindowsID;
  const ucal_getWindowsTimeZoneID_func ucal_getWindowsTimeZoneID;
};

IcuFunctions Unavailable() { return {false, nullptr, nullptr, nullptr}; }

template <typename T>
static T AsProcAddress(HMODULE module, const char* name) {
  static_assert(
      std::is_pointer<T>::value &&
          std::is_function<typename std::remove_pointer<T>::type>::value,
      "T must be a function pointer type");
  const auto proc_address = ::GetProcAddress(module, name);
  return reinterpret_cast<T>(static_cast<void*>(proc_address));
}

IcuFunctions GetIcuFunctions() {
  if (g_unavailable.load(std::memory_order_relaxed)) {
    return Unavailable();
  }

  // Check if already loaded
  {
    const auto ucal_getHostTimeZoneRef =
        g_ucal_getHostTimeZone.load(std::memory_order_relaxed);
    const auto ucal_getTimeZoneIDForWindowsIDRef =
        g_ucal_getTimeZoneIDForWindowsID.load(std::memory_order_relaxed);
    const auto ucal_getWindowsTimeZoneIDRef =
        g_ucal_getWindowsTimeZoneID.load(std::memory_order_relaxed);

    // Note: ucal_getHostTimeZone can be unavailable on older Windows.
    if (ucal_getTimeZoneIDForWindowsIDRef != nullptr &&
        ucal_getWindowsTimeZoneIDRef != nullptr) {
      return {true, ucal_getHostTimeZoneRef, ucal_getTimeZoneIDForWindowsIDRef,
              ucal_getWindowsTimeZoneIDRef};
    }
  }

  // Our goal here is to load the ICU DLL from the system directory, even when
  // the current process has loaded "icu.dll" from somewhere other than the
  // system directory. To do so we must use the full path here.
  std::wstring icu_dll_path;
  {
    const UINT size_with_null = ::GetSystemDirectoryW(nullptr, 0);
    icu_dll_path.reserve(size_with_null + 8);  // +8 for the "\\icu.dll" part
    icu_dll_path.resize(size_with_null);
    const UINT size_without_null =
        ::GetSystemDirectoryW(&icu_dll_path[0], size_with_null);
    if (size_without_null >= icu_dll_path.size()) {
      g_unavailable.store(true, std::memory_order_relaxed);
      return Unavailable();
    }
    icu_dll_path.resize(size_without_null);
    icu_dll_path.append(L"\\icu.dll");
  }
  // CAVEAT: LoadLibraryExW with LOAD_LIBRARY_SEARCH_SYSTEM32 is not
  // sufficient when "icu.dll" is already loaded from somewhere other than
  // the system directory. This is why we must pass a full path here.
  const HMODULE icu_dll = ::LoadLibraryW(icu_dll_path.c_str());
  if (icu_dll == nullptr) {
    g_unavailable.store(true, std::memory_order_relaxed);
    return Unavailable();
  }

  auto ucal_getHostTimeZoneRef =
      AsProcAddress<ucal_getHostTimeZone_func>(icu_dll, "ucal_getHostTimeZone");
  const auto ucal_getTimeZoneIDForWindowsIDRef =
      AsProcAddress<ucal_getTimeZoneIDForWindowsID_func>(
          icu_dll, "ucal_getTimeZoneIDForWindowsID");
  const auto ucal_getWindowsTimeZoneIDRef =
      AsProcAddress<ucal_getWindowsTimeZoneID_func>(
          icu_dll, "ucal_getWindowsTimeZoneID");

  // Note: ucal_getHostTimeZone can be unavailable on older Windows.
  if (!ucal_getTimeZoneIDForWindowsIDRef || !ucal_getWindowsTimeZoneIDRef) {
    g_unavailable.store(true, std::memory_order_relaxed);
    return Unavailable();
  }

  // Store the function pointers
  g_ucal_getHostTimeZone.store(ucal_getHostTimeZoneRef,
                               std::memory_order_relaxed);
  g_ucal_getTimeZoneIDForWindowsID.store(ucal_getTimeZoneIDForWindowsIDRef,
                                         std::memory_order_relaxed);
  g_ucal_getWindowsTimeZoneID.store(ucal_getWindowsTimeZoneIDRef,
                                    std::memory_order_relaxed);

  return {true, ucal_getHostTimeZoneRef, ucal_getTimeZoneIDForWindowsIDRef,
          ucal_getWindowsTimeZoneIDRef};
}

// Convert wchar_t array (UTF-16) to UTF-8 string
std::string Utf16ToUtf8(const wchar_t* ptr, size_t size) {
  if (size > std::numeric_limits<int>::max()) {
    return std::string();
  }
  const int chars_len = static_cast<int>(size);
  int num_bytes_in_utf8 = 0;
  {
    const int buffer_size = 32;
    char buffer[buffer_size];
    num_bytes_in_utf8 =
        ::WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, ptr, chars_len,
                              buffer, buffer_size, nullptr, nullptr);
    if (num_bytes_in_utf8 <= buffer_size) {
      return std::string(buffer, num_bytes_in_utf8);
    }
  }
  auto buffer = std::unique_ptr<char[]>(new char[num_bytes_in_utf8]);
  const int num_written_bytes =
      ::WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, ptr, chars_len,
                            buffer.get(), num_bytes_in_utf8, nullptr, nullptr);
  if (num_written_bytes != num_bytes_in_utf8) {
    return std::string();
  }
  return std::string(buffer.get(), num_written_bytes);
}

}  // namespace

std::string GetWindowsLocalTimeZone() {
  const auto icu = GetIcuFunctions();
  if (!icu.available) {
    return std::string();
  }

  std::int32_t length = 0;

  UErrorCode status = U_ZERO_ERROR;

  // Try ucal_getHostTimeZone first (available on Windows 11+)
  if (icu.ucal_getHostTimeZone != nullptr) {
    const int buffer_size = 32;
    UChar buffer[buffer_size];
    length = icu.ucal_getHostTimeZone(buffer, buffer_size, &status);
    if (U_SUCCESS(status) && length >= 0) {
      return Utf16ToUtf8(buffer, length);
    }
    if (status == U_BUFFER_OVERFLOW_ERROR && length > 0) {
      const int buffer_size = length + 1;  // +1 for null terminator
      auto buffer = std::unique_ptr<UChar[]>(new UChar[buffer_size]);
      status = U_ZERO_ERROR;
      length = icu.ucal_getHostTimeZone(buffer.get(), buffer_size, &status);
      if (U_SUCCESS(status) && length >= 0) {
        return Utf16ToUtf8(buffer.get(), length);
      }
    }
  }

  DYNAMIC_TIME_ZONE_INFORMATION info = {};
  if (::GetDynamicTimeZoneInformation(&info) == TIME_ZONE_ID_INVALID) {
    return std::string();
  }
  {
    const int buffer_size = 32;
    UChar buffer[buffer_size];
    status = U_ZERO_ERROR;
    length = icu.ucal_getTimeZoneIDForWindowsID(
        info.TimeZoneKeyName, -1, nullptr, buffer, buffer_size, &status);
    if (U_SUCCESS(status) && length >= 0) {
      return Utf16ToUtf8(buffer, length);
    }
    if (status != U_BUFFER_OVERFLOW_ERROR || length <= 0) {
      return std::string();
    }
  }
  const int buffer_size = length + 1;  // +1 for null terminator
  auto buffer = std::unique_ptr<UChar[]>(new UChar[buffer_size]);
  status = U_ZERO_ERROR;
  length = icu.ucal_getTimeZoneIDForWindowsID(
      info.TimeZoneKeyName, -1, nullptr, buffer.get(), buffer_size, &status);
  if (U_SUCCESS(status) && length >= 0) {
    return Utf16ToUtf8(buffer.get(), length);
  }
  return std::string();
}

std::wstring ConvertToWindowsTimeZoneId(const std::wstring& iana_name) {
  const auto icu = GetIcuFunctions();
  if (!icu.available) {
    return std::wstring();
  }
  if (iana_name.size() > std::numeric_limits<std::int32_t>::max()) {
    return std::wstring();
  }
  const std::int32_t iana_name_length =
      static_cast<std::int32_t>(iana_name.size());

  const std::int32_t buffer_size = kWindowsTimeZoneNameMax;
  UChar buffer[buffer_size];
  UErrorCode status = U_ZERO_ERROR;
  const std::int32_t length = icu.ucal_getWindowsTimeZoneID(
      iana_name.c_str(), iana_name_length, buffer, buffer_size, &status);
  if (U_SUCCESS(status) && length > 0) {
    return std::wstring(buffer, length);
  }
  return std::wstring();
}

}  // namespace icu
}  // namespace cctz

#endif
