#define GFBITS 12
#define SYS_T 62

#define PK_NROWS (SYS_T * GFBITS)
#define PK_NCOLS ((1 << GFBITS) - SYS_T * GFBITS)

#define IRR_BYTES (GFBITS * 8)
#define COND_BYTES (736 * 8)
#define SYND_BYTES (PK_NROWS / 8)
