/* Extras for OQS extension */

#define ENCODE_UINT32(pbuf, i)  (pbuf)[index]   = (unsigned char)((i>>24) & 0xff); \
                                (pbuf)[index+1] = (unsigned char)((i>>16) & 0xff); \
                                (pbuf)[index+2] = (unsigned char)((i>> 8) & 0xff); \
                                (pbuf)[index+3] = (unsigned char)((i    ) & 0xff)
#define DECODE_UINT32(i, pbuf)  i  = ((uint32_t) (pbuf)[index])   << 24; \
                                i |= ((uint32_t) (pbuf)[index+1]) << 16; \
                                i |= ((uint32_t) (pbuf)[index+2]) <<  8; \
                                i |= ((uint32_t) (pbuf)[index+3])

/* Encodes two messages (classical and PQC) into one hybrid message:
   msg1_len || msg1 || msg2_len || msg2
   hybrid_msg is allocated in this function.
 */
static int OQS_encode_hybrid_message(const unsigned char* msg1, uint32_t  msg1_len,
                                     const unsigned char* msg2, uint32_t  msg2_len,
                                     unsigned char** hybrid_msg, uint32_t* hybrid_msg_len) {
  int index = 0;
  *hybrid_msg_len = msg1_len + msg2_len + (2 * sizeof(uint32_t));
  *hybrid_msg = OPENSSL_malloc(*hybrid_msg_len);
  if (*hybrid_msg == NULL) {
    return 0;
  }

  ENCODE_UINT32(*hybrid_msg, msg1_len);  
  index += sizeof(uint32_t);
  memcpy(*hybrid_msg + index, msg1, msg1_len);
  index += msg1_len;

  ENCODE_UINT32(*hybrid_msg, msg2_len);  
  index += sizeof(uint32_t);
  memcpy(*hybrid_msg + index, msg2, msg2_len);
  
  return 1;
}

/* Decodes hybrid message returning the classical and PQC messages:
   msg1_len || msg1 || msg2_len || msg2
   msg1 and msg2 are allocated in this function.
 */
static int OQS_decode_hybrid_message(const unsigned char* hybrid_msg,
                                     unsigned char** msg1, uint32_t* msg1_len,
                                     unsigned char** msg2, uint32_t* msg2_len) {
  int index = 0;
  DECODE_UINT32(*msg1_len, hybrid_msg);
  index += sizeof(uint32_t);
  *msg1 = OPENSSL_malloc(*msg1_len);
  if (*msg1 == NULL) {
    return 0;
  }
  memcpy(*msg1, hybrid_msg + index, *msg1_len);
  index += *msg1_len;

  DECODE_UINT32(*msg2_len, hybrid_msg);
  index += sizeof(uint32_t);
  *msg2 = OPENSSL_malloc(*msg2_len);
  if (*msg2 == NULL) {
    return 0;
  }
  memcpy(*msg2, hybrid_msg + index, *msg2_len);

  return 1;
}
