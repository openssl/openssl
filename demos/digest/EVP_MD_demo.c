/*-
 * Copyright 2019-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Example of using EVP_MD_fetch and EVP_Digest* methods to calculate
 * a digest of static buffers
 */

#include <string.h>
#include <stdio.h>
#include <openssl/err.h>
#include <openssl/evp.h>

/*-
 * This demonstration will show how to digest data using
 * the soliloqy from Hamlet scene 1 act 3
 * The soliloqy is split into two parts to demonstrate using EVP_DigestUpdate
 * more than once.
 */

const char * hamlet_1 =
	"To be, or not to be, that is the question,\n"
	"Whether tis nobler in the minde to suffer\n"
	"The ſlings and arrowes of outragious fortune,\n"
	"Or to take Armes again in a sea of troubles,\n"
	"And by opposing, end them, to die to sleep;\n"
	"No more, and by a sleep, to say we end\n"
	"The heart-ache, and the thousand natural shocks\n"
	"That flesh is heir to? tis a consumation\n"
	"Devoutly to be wished. To die to sleep,\n"
	"To sleepe, perchance to dreame, Aye, there's the rub,\n"
	"For in that sleep of death what dreams may come\n"
	"When we haue shuffled off this mortal coil\n"
	"Must give us pause. There's the respect\n"
	"That makes calamity of so long life:\n"
	"For who would bear the Ships and Scorns of time,\n"
	"The oppressor's wrong, the proud man's Contumely,\n"
	"The pangs of dispised love, the Law's delay,\n"
;
const char * hamlet_2 =
	"The insolence of Office, and the spurns\n"
	"That patient merit of the'unworthy takes,\n"
	"When he himself might his Quietas make\n"
	"With a bare bodkin? Who would fardels bear,\n"
	"To grunt and sweat under a weary life,\n"
	"But that the dread of something after death,\n"
	"The undiscovered country, from whose bourn\n"
	"No traveller returns, puzzles the will,\n"
	"And makes us rather bear those ills we have,\n"
	"Then fly to others we know not of?\n"
	"Thus conscience does make cowards of us all,\n"
	"And thus the native hue of Resolution\n"
	"Is sickled o'er with the pale cast of Thought,\n"
	"And enterprises of great pith and moment,\n"
	"With this regard their currents turn awry,\n"
	"And lose the name of Action. Soft you now,\n"
	"The fair Ophelia? Nymph in thy Orisons\n"
	"Be all my sins remember'd.\n"
; 

/*
 * The known value of the SHA3-512 digest of the above soliloqy
 */
const unsigned char known_answer[] = {
	0xbb, 0x69, 0xf8, 0x09, 0x9c, 0x2e, 0x00, 0x3d,
	0xa4, 0x29, 0x5f, 0x59, 0x4b, 0x89, 0xe4, 0xd9,
	0xdb, 0xa2, 0xe5, 0xaf, 0xa5, 0x87, 0x73, 0x9d,
	0x83, 0x72, 0xcf, 0xea, 0x84, 0x66, 0xc1, 0xf9,
	0xc9, 0x78, 0xef, 0xba, 0x3d, 0xe9, 0xc1, 0xff,
	0xa3, 0x75, 0xc7, 0x58, 0x74, 0x8e, 0x9c, 0x1d,
	0x14, 0xd9, 0xdd, 0xd1, 0xfd, 0x24, 0x30, 0xd6,
	0x81, 0xca, 0x8f, 0x78, 0x29, 0x19, 0x9a, 0xfe,
};

int demonstrate_digest(void) {
	OSSL_LIB_CTX	*library_context;
	int result = 0;

	library_context = OSSL_LIB_CTX_new();
	if (library_context == NULL) {
		fprintf(stderr, "OSSL_LIB_CTX_new() returned NULL\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}

	/*
	 * Fetch a message digest by name
	 */
	const char * digest_name = "SHA3-512";
	const char * option_properties = NULL;
	EVP_MD *message_digest = EVP_MD_fetch(library_context,
								digest_name, option_properties);
	if (message_digest == NULL) {
		fprintf(stderr, "EVP_MD_fetch could not find %s.", digest_name);
        ERR_print_errors_fp(stderr);
		OSSL_LIB_CTX_free(library_context);
		return 0;
	}
/*
 * Determine the length of the fetched digest type
 */
	unsigned int digest_length = EVP_MD_size(message_digest);
	if (digest_length <= 0) {
		fprintf(stderr, "EVP_MD_size returned invalid size.\n");
		goto cleanup_md;
	}

	unsigned char *digest_value = malloc(digest_length);
	if (digest_value == NULL) {
		fprintf(stderr, "No memory.\n");
		goto cleanup_md;
	}
/*
 * Make a message digest context to hold temporary state
 * during digest creation
 */
	EVP_MD_CTX *digest_context = EVP_MD_CTX_new();
	if (digest_context == NULL) {
		fprintf(stderr, "EVP_MD_CTX_new failed.\n");
        ERR_print_errors_fp(stderr);
		goto cleanup_md;
	}
/*
 * Initialize the message digest context to use the fetched 
 * digest provider
 */
	if (EVP_DigestInit(digest_context, message_digest) != 1) {
		fprintf(stderr, "EVP_DigestInit failed.\n");
        ERR_print_errors_fp(stderr);
		goto cleanup_md_ctx;
	}
/*
 * Digest parts one and two of the soliloqy
 */
	if (EVP_DigestUpdate(digest_context, hamlet_1, strlen(hamlet_1)) != 1) {
		fprintf(stderr, "EVP_DigestUpdate(hamlet_1) failed.\n");
        ERR_print_errors_fp(stderr);
		goto cleanup_md_ctx;
	}
	if (EVP_DigestUpdate(digest_context, hamlet_2, strlen(hamlet_2)) != 1) {
		fprintf(stderr, "EVP_DigestUpdate(hamlet_2) failed.\n");
        ERR_print_errors_fp(stderr);
		goto cleanup_md_ctx;
	}
	if (EVP_DigestFinal(digest_context, digest_value, &digest_length) != 1) {
		fprintf(stderr, "EVP_DigestFinal() failed.\n");
        ERR_print_errors_fp(stderr);
		goto cleanup_md_ctx;
	}
	for( int ii=0; ii<digest_length; ii++ ) {
		fprintf(stdout, "%2.2x", digest_value[ii]);
	}
	fprintf(stdout, "\n");
/*
 * Check digest_value against the known answer
 */
	if ((size_t)digest_length != sizeof(known_answer)) {
		fprintf(stdout, "Digest length(%d) not equal to known answer length(%lu).\n",
			digest_length, sizeof(known_answer));
	} else if (memcmp(digest_value, known_answer, digest_length) != 0) {
		for( int ii=0; ii<sizeof(known_answer); ii++ ) {
			fprintf(stdout, "%2.2x", known_answer[ii] );
		}
		fprintf(stdout, "\nDigest does not match known answer\n");
	} else {
		fprintf(stdout, "Digest computed properly.\n");
		result = 1;
	}

cleanup_md_ctx:
	EVP_MD_CTX_free(digest_context);

cleanup_md:
	free(digest_value);
	EVP_MD_free(message_digest);

	OSSL_LIB_CTX_free(library_context);
	return result;
}

int main(void) {
	return demonstrate_digest() == 0;
}
