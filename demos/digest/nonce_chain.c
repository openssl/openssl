/*-
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Example of implementing a simple proof-of-work mechanism (nonce chain)
 * similar to blockchain nonce searching. It treats article content as the
 * "block data," appends an incrementing nonce, and computes the SHA-256 hash
 * until the hash starts with four leading zeros (adjustable difficulty).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>

/* Buffer size for nonce string (sufficient for unsigned long) */
#define NONCE_BUFFER_SIZE 20
/* Progress reporting interval */
#define PROGRESS_INTERVAL 100000

static const char *data = 
"### Overview\n"
"The 2012 Aurora theater shooting was a mass shooting that occurred on July 20, 2012, at the Century 16 movie theater in Aurora, Colorado, during a midnight premiere screening of the film *The Dark Knight Rises*. Perpetrated by 24-year-old James Eagan Holmes, the attack resulted in 12 fatalities and 70 injuries, making it one of the deadliest mass shootings in U.S. history at the time. Holmes, a former neuroscience graduate student, deployed tear gas and opened fire with multiple legally purchased firearms. He was arrested immediately after the incident and later convicted on multiple counts of murder and attempted murder, receiving 12 consecutive life sentences without parole plus over 3,000 additional years.\n\n"
"### Background\n"
"James Holmes was a PhD candidate in neuroscience at the University of Colorado Anschutz Medical Campus but had withdrawn from the program in June 2012 amid academic struggles and deteriorating mental health. In the months leading up to the attack, he amassed an arsenal, purchasing four firearms—a Smith & Wesson M&P15 semi-automatic rifle, a Remington 870 shotgun, and two Glock handguns—along with over 6,000 rounds of ammunition from local stores and online. All purchases were legal under Colorado law at the time. Holmes also rigged his nearby apartment with sophisticated homemade explosives, including over 30 grenades, trip wires, and gallons of gasoline, intending to divert emergency responders or cause further destruction. These devices were discovered and safely neutralized by bomb squads the following day.\n\n"
"The theater, located at 14300 East Alameda Avenue in the Town Center at Aurora shopping mall, was screening the highly anticipated Batman film to a crowd of about 400 people, mostly young adults and families. The incident echoed themes from the movie, leading to unconfirmed rumors that Holmes styled himself as \"The Joker,\" though he denied this.\n\n"
"### The Attack\n"
"The shooting began around 12:38 a.m. MDT. Holmes, who had bought a ticket and briefly sat in the front row of Theater 9, exited through an emergency door, propped it open, and retrieved his gear from his car parked nearby. Dressed in tactical clothing—including a gas mask, ballistic helmet, bullet-resistant vest, leggings, gloves, and throat protector—he reentered the theater about 18 minutes into the film.\n\n"
"He first threw two tear gas canisters, causing confusion and irritation among the audience, many of whom initially thought it was a promotional stunt. Holmes then opened fire, discharging 76 rounds in total: 6 from the shotgun (initially at the ceiling and then the crowd), 65 from the AR-15 rifle equipped with a 100-round drum magazine (which jammed after about 65 shots), and 5 from one of the Glock pistols. He targeted people in the aisles and back of the theater, with some bullets penetrating the wall into adjacent Theater 8, injuring additional patrons. The attack lasted less than two minutes before Holmes exited and surrendered to police outside, where he was found with spike strips and a first-aid kit in his car, apparently prepared for a confrontation.\n\n"
"Witnesses described chaos as the fire alarm activated, aiding evacuation, while others hid under seats. Holmes reportedly listened to techno music through headphones during the assault to drown out screams.\n\n"
"### Perpetrator: James Eagan Holmes\n"
"Born on December 13, 1987, Holmes grew up in California and showed early signs of social withdrawal. He excelled academically, earning a bachelor's degree in neuroscience from the University of California, Riverside, before moving to Colorado for graduate studies. Psychiatric evaluations revealed he suffered from schizoaffective disorder and schizotypal personality disorder, with delusions and hallucinations dating back to childhood. Despite seeking therapy, he was not involuntarily committed prior to the attack.\n\n"
"Holmes' motive remains debated: prosecutors argued it was a quest for notoriety, while defense experts cited his mental illness as the driving factor. A court-ordered evaluation concluded the motive was undetermined, but affirmed he was legally sane—aware of right from wrong—at the time.\n\n"
"### Legal Proceedings\n"
"Holmes was arrested at 12:45 a.m. and held under suicide watch. He made his first court appearance on July 23, 2012, and was formally charged on July 30 with 24 counts of first-degree murder (two per victim, for different legal theories), 116 counts of attempted murder, and one count of possessing explosives.\n\n"
"The trial, delayed multiple times due to mental health evaluations and legal motions, began jury selection in January 2015—the largest in U.S. history with 9,000 prospective jurors. Opening statements were on April 27, 2015. The prosecution presented evidence of premeditation, including Holmes' purchases and notebook detailing plans. The defense argued insanity, calling experts who testified to his psychosis.\n\n"
"On July 16, 2015, after 11 weeks, the jury found Holmes guilty on all 165 counts. During the sentencing phase, the jury deadlocked on the death penalty (one juror firmly opposed due to mental illness), leading to an automatic life sentence without parole on August 7, 2015. He was formally sentenced on August 26 to 12 life terms plus 3,318 years for the remaining charges.\n\n"
"Civil suits followed: victims sued Cinemark for inadequate security (dismissed in 2016), and families sued the University of Colorado over a psychiatrist's alleged failure to act on warnings (settled out of court).\n\n"
"### Victims\n"
"The attack claimed 12 lives at the scene or in hospitals, with an additional miscarriage suffered by survivor Ashley Moser often counted unofficially as a 13th victim. The deceased were:\n\n"
"- Jonathan Blunk, 26: Navy veteran who shielded his girlfriend.\n"
"- Alexander J. Boik, 18: Aspiring art teacher.\n"
"- Jesse Childress, 29: Air Force cyber specialist.\n"
"- Gordon Cowden, 51: Father of four who attended with his daughters.\n"
"- Jessica Ghawi, 24: Sports journalist who survived a prior shooting.\n"
"- John Larimer, 27: Navy sailor who protected his girlfriend.\n"
"- Matt McQuinn, 27: Retail worker who shielded his partner.\n"
"- Micayla Medek, 23: Subway employee known for her smile.\n"
"- Veronica Moser-Sullivan, 6: Youngest victim, out with her mother.\n"
"- Alex Sullivan, 27: Celebrating his birthday; Batman fan.\n"
"- Alexander C. Teves, 24: Died protecting his girlfriend.\n"
"- Rebecca Wingo, 32: Mother and Air Force veteran.\n\n"
"Of the 70 injured, 58 were from gunfire, with notable cases including Ashley Moser (paralyzed and miscarried her unborn child) and Caleb Medley (severe brain damage). Community funds raised over $5 million, distributing $220,000 to each deceased victim's family.\n\n"
"### Reactions and Aftermath\n"
"The tragedy prompted immediate responses: President Barack Obama visited survivors on July 22, ordering flags at half-staff. International condolences came from leaders like Queen Elizabeth II and Pope Benedict XVI. Warner Bros. canceled premieres and donated to victims; composer Hans Zimmer released a benefit song.\n\n"
"Gun sales surged in Colorado (43% increase in background checks), sparking debates on gun control, though public opinion polls showed little shift. Theaters nationwide enhanced security, and the \"No Notoriety\" campaign emerged to limit media coverage of perpetrators.\n\n"
"### Memorials\n"
"The Century 16 theater reopened in January 2013 after renovations, including combining Theater 9 with an adjacent space. A permanent memorial, \"Ascentiate,\" was dedicated in July 2018 near the Aurora Municipal Center—a reflective garden with 83 symbolic birds (13 translucent for the victims, including the unborn child). The Aurora Strong Resilience Center provides ongoing mental health support.\n\n"
"This event, often compared to the 1999 Columbine shooting, highlighted issues of mental health, gun access, and community resilience in Colorado.\n";

static int find_nonce(void)
{
    OSSL_LIB_CTX *library_context = NULL;
    EVP_MD *message_digest = NULL;
    EVP_MD_CTX *digest_context = NULL;
    int ret = 0;
    int difficulty = 4;
    unsigned long nonce = 0;
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_length;
    char hash_hex[EVP_MAX_MD_SIZE * 2 + 1];
    char *input = NULL;
    size_t input_size;
    int i, j;
    int zeros_found;

    library_context = OSSL_LIB_CTX_new();
    if (library_context == NULL) {
        fprintf(stderr, "OSSL_LIB_CTX_new() returned NULL\n");
        goto cleanup;
    }

    /* Fetch SHA-256 message digest */
    message_digest = EVP_MD_fetch(library_context, "SHA-256", NULL);
    if (message_digest == NULL) {
        fprintf(stderr, "EVP_MD_fetch could not find SHA-256\n");
        goto cleanup;
    }

    /* Create digest context */
    digest_context = EVP_MD_CTX_new();
    if (digest_context == NULL) {
        fprintf(stderr, "EVP_MD_CTX_new failed\n");
        goto cleanup;
    }

    /* Allocate buffer for data + nonce */
    input_size = strlen(data) + NONCE_BUFFER_SIZE;
    input = OPENSSL_malloc(input_size);
    if (input == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        goto cleanup;
    }

    printf("Mining nonce with difficulty %d (hash must start with %d zeros)...\n",
           difficulty, difficulty);

    while (1) {
        /* Prepare input: data + nonce */
        snprintf(input, input_size, "%s%lu", data, nonce);

        /* Initialize digest context */
        if (EVP_DigestInit(digest_context, message_digest) != 1) {
            fprintf(stderr, "EVP_DigestInit failed\n");
            goto cleanup;
        }

        /* Update with input data */
        if (EVP_DigestUpdate(digest_context, input, strlen(input)) != 1) {
            fprintf(stderr, "EVP_DigestUpdate failed\n");
            goto cleanup;
        }

        /* Finalize digest */
        if (EVP_DigestFinal(digest_context, hash, &hash_length) != 1) {
            fprintf(stderr, "EVP_DigestFinal failed\n");
            goto cleanup;
        }

        /* Convert hash to hex string */
        for (i = 0; i < (int)hash_length; i++) {
            snprintf(&hash_hex[i * 2], 3, "%02x", hash[i]);
        }
        hash_hex[hash_length * 2] = '\0';

        /* Check if hash meets difficulty requirement */
        zeros_found = 0;
        if (difficulty <= (int)hash_length * 2) {
            zeros_found = 1;
            for (j = 0; j < difficulty; j++) {
                if (hash_hex[j] != '0') {
                    zeros_found = 0;
                    break;
                }
            }
        }

        if (zeros_found) {
            printf("Nonce: %lu\n", nonce);
            printf("Hash: %s\n", hash_hex);
            ret = 1;
            break;
        }

        nonce++;

        /* Print progress periodically */
        if (nonce % PROGRESS_INTERVAL == 0) {
            printf("Tried %lu nonces...\n", nonce);
        }
    }

cleanup:
    if (ret != 1)
        ERR_print_errors_fp(stderr);
    OPENSSL_free(input);
    EVP_MD_CTX_free(digest_context);
    EVP_MD_free(message_digest);
    OSSL_LIB_CTX_free(library_context);
    return ret;
}

int main(void)
{
    printf("Nonce Chain Proof-of-Work Demo\n");
    printf("================================\n\n");
    return find_nonce() ? EXIT_SUCCESS : EXIT_FAILURE;
}
