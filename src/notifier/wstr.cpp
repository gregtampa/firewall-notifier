#include "wstr.h"
#include <assert.h>
#include <wchar.h>

size_t wcshash(wchar_t const* src) {
	assert(src);

	/* FNV1-a: http://www.isthe.com/chongo/tech/comp/fnv/ */
	size_t hash = 14695981039346656037;

	for (size_t i = 0; src[i]; ++i) {
		hash ^= src[i];
		hash *= 1099511628211;
	}

	return hash;
}

void wcsmerge(wchar_t* dst, size_t dst_count, wchar_t const* src1, wchar_t const* src2) {
	assert(dst);
	assert(dst_count);
	assert(src1);
	assert(src2);

	size_t di;
	for (di = 0; di < dst_count && src1[di]; ++di) {
		dst[di] = src1[di];
	}

	size_t si;
	for (si = 0; di < dst_count && src2[si]; ++si, ++di) {
		dst[di] = src2[si];
	}

	di = (di == dst_count) ? di - 1 : di;
	dst[di] = 0;
}
