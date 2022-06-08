/*
 * This file is a C++ adapataion by Tom Bennet of the plain C code by 
 * Brad Conte, as noted below.  This original code does all the actual
 * work of computing the sha256 sum.
 */

/*********************************************************************
* Filename:   sha256.h
* Author:     Brad Conte (brad AT bradconte.com)
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Defines the API for the corresponding SHA1 implementation.
*********************************************************************/

#ifndef SHA256_H
#define SHA256_H

/*************************** HEADER FILES ***************************/
#include <cstddef>
#include <cstdio>
#include <stdint.h>

#include <string>

class sha256 {
public:
	typedef unsigned char BYTE;     // 8-bit byte
	typedef uint32_t WORD;

	// Construct the object, optionally giving it some data to
	// process.
	sha256() { 
		init(&m_context);
	}
	sha256(BYTE data[], int size) {
		init(&m_context);
		process(data, size);
	}
	sha256(const std::string &s) {
		init(&m_context);
		process(s);
	}

	// Discard state and start over.  

	// Process data.  Returns the object to allow chaining.
	sha256 & process(BYTE data[], int size) {
		update(&m_context, data, size);
		return *this;
	}
	sha256 & process(const std::string &s) {
		process((BYTE *)s.data(), s.length());
		return *this;
	}

	// Clear the current computation and discard its result.  You may then
	// use the object for a new computation.
	void reset() { init(&m_context); }

	// ** All the get methods complete and return the sum, and 
	// ** clear the object state.  You can only get a result once.
	// ** You may then use the object to compute another sum.

	// Finish, and get the result as a string of _binary_ data.
	std::string get() {
		BYTE result[BLOCK_SIZE];
		get(result);
		return std::string((char*)result, BLOCK_SIZE);
	}

	// Finish, and get the result as a hexadecimal string suitable
	// for printing.
	std::string getx();

	// Finish, and get the result as an array of bytes (unsigned 
	// characters) output through the parameter.  This array must
	// have room for BLOCK_SIZE bytes.
	void get(unsigned char buf[]) {
		final(&m_context, buf);
		init(&m_context);		
	}

	// This is the byte size of the SHA sum.
	static const int BLOCK_SIZE = 32;
private:

	typedef struct {
		BYTE data[64];
		WORD datalen;
		unsigned long long bitlen;
		WORD state[8];
	} SHA256_CTX;

	// Translation context.
	SHA256_CTX m_context;

	// Internal constants.
	static const WORD k[64];
	
	void init(SHA256_CTX *ctx);
	void update(SHA256_CTX *ctx, const BYTE data[], size_t len);
	void final(SHA256_CTX *ctx, BYTE hash[]);

	void transform(SHA256_CTX *ctx, const BYTE data[]);
};

#endif   // SHA256_H
