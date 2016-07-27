#pragma once

// Signed integer types.
typedef char i8;
typedef short i16;
typedef int i32;
typedef long long int i64;

// Unsigned integer types.
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long int u64;

// Floating point types.
typedef float f32;
typedef double f64;

// Boolean type.
typedef u32 b32;

// Native size type.
__if_not_exists(size_t) { typedef u64 size_t; }

// Aligns the value to a byte boundary specified by x.
#define ALIGN(x) __declspec(align(x))

// The maximum extended path length.
#define MAX_EXT_PATH 32767

// Returns the value x clamped between the low and high values.
template <typename T, typename U>
constexpr const T CLAMP(const T& x, const U& low, const U& high) {
	return x > high ? high : (x < low ? low : x);
}

// Returns the number of elements in a array.
template <typename T, size_t n>
constexpr size_t COUNT(T const (&x)[n]) {
	return n;
}

// Returns the maximum of x or y.
template <typename T>
constexpr const T MAX(const T& x, const T& y) {
	return x > y ? x : y;
}

// Returns the minimum of x or y.
template <typename T>
constexpr const T MIN(const T& x, const T& y) {
	return x < y ? x : y;
}
