#pragma once
#include "core.h"

// Returns the 64-bit hash of the given string.
size_t wcshash(wchar_t const* src);

// Merges two strings, such that dst = src1 + src2. Truncates to ensure that the string is null terminated.
void wcsmerge(wchar_t* dst, size_t dst_count, wchar_t const* src1, wchar_t const* src2);
