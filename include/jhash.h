
#ifndef JHASH_H
#define JHASH_H

/* 
	this implementation of jhash is copied 
 	from https://github.com/torvalds/linux/blob/master/include/linux/jhash.h
*/

#include <stdint.h>
#define JHASH_INITVAL		0xdeadbeef

static inline uint32_t rol32(uint32_t word, unsigned int shift)
{
    return (word << shift) | (word >> (32 - shift));
}

/* __jhash_final - final mixing of 3 32-bit values (a,b,c) into c */
#define __jhash_final(a, b, c)			\
{						\
	c ^= b; c -= rol32(b, 14);		\
	a ^= c; a -= rol32(c, 11);		\
	b ^= a; b -= rol32(a, 25);		\
	c ^= b; c -= rol32(b, 16);		\
	a ^= c; a -= rol32(c, 4);		\
	b ^= a; b -= rol32(a, 14);		\
	c ^= b; c -= rol32(b, 24);		\
}

/* __jhash_nwords - hash exactly 3, 2 or 1 word(s) */
static inline uint32_t __jhash_nwords(uint32_t a, uint32_t b, uint32_t c, uint32_t initval)
{
	a += initval;
	b += initval;
	c += initval;

	__jhash_final(a, b, c);

	return c;
}

static inline uint32_t jhash_3words(uint32_t a, uint32_t b, uint32_t c, uint32_t initval)
{
	return __jhash_nwords(a, b, c, initval + JHASH_INITVAL + (3 << 2));
}


#endif /* JHASH_H */