/*
 * htonll source from internet
 *
 * Copyright (C) 2013 honeysense.com
 * @author rui.sun 2013-8-15
 */
#ifndef HTONLL_H
#define HTONLL_H

#if defined(WIN32) && !defined(__BYTE_ORDER)
#define __BYTE_ORDER __LITTLE_ENDIAN
#endif

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define htonll(x) bswap_64(x)
#define ntohll(x) bswap_64(x)
#else
#define htonll(x) x
#define ntohll(x) x
#endif

#ifdef _MSC_VER

static _inline uint16_t bswap_16(register uint16_t x)
{
    return ((uint16_t)( \
		(((uint16_t)(x) & (uint16_t)0x00ffU) << 8) | \
		(((uint16_t)(x) & (uint16_t)0xff00U) >> 8) )); \
}

static _inline uint32_t bswap_32(register uint32_t x) \
{ \
    return ((uint32_t)( \
		(((uint32_t)(x) & (uint32_t)0x000000ffUL) << 24) | \
		(((uint32_t)(x) & (uint32_t)0x0000ff00UL) <<  8) | \
		(((uint32_t)(x) & (uint32_t)0x00ff0000UL) >>  8) | \
		(((uint32_t)(x) & (uint32_t)0xff000000UL) >> 24) )); \
}

static _inline uint64_t bswap_64(register uint64_t x) \
{ \
    return ((uint64_t)( \
		(uint64_t)(((uint64_t)(x) & (uint64_t)0x00000000000000ffULL) << 56) | \
		(uint64_t)(((uint64_t)(x) & (uint64_t)0x000000000000ff00ULL) << 40) | \
		(uint64_t)(((uint64_t)(x) & (uint64_t)0x0000000000ff0000ULL) << 24) | \
		(uint64_t)(((uint64_t)(x) & (uint64_t)0x00000000ff000000ULL) <<  8) | \
		(uint64_t)(((uint64_t)(x) & (uint64_t)0x000000ff00000000ULL) >>  8) | \
		(uint64_t)(((uint64_t)(x) & (uint64_t)0x0000ff0000000000ULL) >> 24) | \
		(uint64_t)(((uint64_t)(x) & (uint64_t)0x00ff000000000000ULL) >> 40) | \
		(uint64_t)(((uint64_t)(x) & (uint64_t)0xff00000000000000ULL) >> 56) )); \
}

#else

#define bswap_16(x) __extension__ /** <- VBOX */ \
({ \
	uint16_t __x = (x); \
	((uint16_t)( \
	(((uint16_t)(__x) & (uint16_t)0x00ffU) << 8) | \
	(((uint16_t)(__x) & (uint16_t)0xff00U) >> 8) )); \
})

#define bswap_32(x) __extension__ /** <- VBOX */ \
({ \
	uint32_t __x = (x); \
	((uint32_t)( \
	(((uint32_t)(__x) & (uint32_t)0x000000ffUL) << 24) | \
	(((uint32_t)(__x) & (uint32_t)0x0000ff00UL) <<  8) | \
	(((uint32_t)(__x) & (uint32_t)0x00ff0000UL) >>  8) | \
	(((uint32_t)(__x) & (uint32_t)0xff000000UL) >> 24) )); \
})

#define bswap_64(x) __extension__ /** <- VBOX */ \
({ \
	uint64_t __x = (x); \
	((uint64_t)( \
	(uint64_t)(((uint64_t)(__x) & (uint64_t)0x00000000000000ffULL) << 56) | \
	(uint64_t)(((uint64_t)(__x) & (uint64_t)0x000000000000ff00ULL) << 40) | \
	(uint64_t)(((uint64_t)(__x) & (uint64_t)0x0000000000ff0000ULL) << 24) | \
	(uint64_t)(((uint64_t)(__x) & (uint64_t)0x00000000ff000000ULL) <<  8) | \
	(uint64_t)(((uint64_t)(__x) & (uint64_t)0x000000ff00000000ULL) >>  8) | \
	(uint64_t)(((uint64_t)(__x) & (uint64_t)0x0000ff0000000000ULL) >> 24) | \
	(uint64_t)(((uint64_t)(__x) & (uint64_t)0x00ff000000000000ULL) >> 40) | \
	(uint64_t)(((uint64_t)(__x) & (uint64_t)0xff00000000000000ULL) >> 56) )); \
})

#endif

#endif