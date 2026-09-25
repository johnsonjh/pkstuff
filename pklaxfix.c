/*****************************************************************************/

/*
 * PKLAXFIX: PKLITE <1.50 Executable Postprocessor (fixes AX restore bug)
 * Copyright (c) 1993-2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>
 * Copyright (c) 2023-2026 Jason Summers <jason1@pobox.com>
 * SPDX-License-Identifer: MIT
 * scspell-id: baa28f58-b88c-11f1-9f53-80ee73e9b8e7
 */

/*****************************************************************************/

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*****************************************************************************/

/* "PKlite(" */
static const unsigned char PAT_WIN3_PK1[]
    = { 0x50, 0x4b, 0x6c, 0x69, 0x74, 0x65, 0x28 };
#define PAT_WIN3_PK1_LEN ((long)sizeof (PAT_WIN3_PK1))

/*****************************************************************************/

/* "Pklite(" */
static const unsigned char PAT_WIN3_PK2[]
    = { 0x50, 0x6b, 0x6c, 0x69, 0x74, 0x65, 0x28 };
#define PAT_WIN3_PK2_LEN ((long)sizeof (PAT_WIN3_PK2))

/*****************************************************************************/

/* beta EXE structure, variant 1 */
static const unsigned char PAT_ISBETA1[]
    = { 0x2e, 0x8c, 0x1e, 0x3f, 0x3f, 0x8b, 0x1e, 0x3f, 0x3f,
        0x8c, 0xda, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0x72 };
#define PAT_ISBETA1_LEN ((long)sizeof (PAT_ISBETA1))

/*****************************************************************************/

/* beta EXE structure, variant 2 (load-high) */
static const unsigned char PAT_ISBETA2[]
    = { 0x2e, 0x8c, 0x1e, 0x3f, 0x3f, 0xfc, 0x8c, 0xc8 };
#define PAT_ISBETA2_LEN ((long)sizeof (PAT_ISBETA2))

/*****************************************************************************/

/* mov ax,imm16 / mov dx,?? (4 bytes) */
static const unsigned char PAT_SHORT4[]
    = { 0xb8, 0x3f, 0x3f, 0xba };
#define PAT_SHORT4_LEN ((long)sizeof (PAT_SHORT4))

/*****************************************************************************/

/* push ax / mov ax,imm16 / mov dx,?? (5 bytes) */
static const unsigned char PAT_SHORT5[]
    = { 0x50, 0xb8, 0x3f, 0x3f, 0xba };
#define PAT_SHORT5_LEN ((long)sizeof (PAT_SHORT5))

/*****************************************************************************/

/* intro variant 1.00 */
static const unsigned char PAT_V100[]
    = { 0xb8, 0x3f, 0x3f, 0xba, 0x3f, 0x3f, 0x8c, 0xdb,
        0x03, 0xd8, 0x3b, 0x1e, 0x02, 0x00, 0x73 };
#define PAT_V100_LEN ((long)sizeof (PAT_V100))

/*****************************************************************************/

/* intro variant 1.12 */
static const unsigned char PAT_V112[]
    = { 0xb8, 0x3f, 0x3f, 0xba, 0x3f, 0x3f, 0x05,
        0x00, 0x00, 0x3b, 0x06, 0x02, 0x00, 0x73 };
#define PAT_V112_LEN ((long)sizeof (PAT_V112))

/*****************************************************************************/

/* intro variant 1.14 */
static const unsigned char PAT_V114[]
    = { 0xb8, 0x3f, 0x3f, 0xba, 0x3f, 0x3f, 0x05,
        0x00, 0x00, 0x3b, 0x06, 0x02, 0x00, 0x72 };
#define PAT_V114_LEN ((long)sizeof (PAT_V114))

/*****************************************************************************/

/* intro variant MEGALITE */
static const unsigned char PAT_MEGALITE[]
    = { 0xb8, 0x3f, 0x3f, 0xba, 0x3f, 0x3f, 0x05,
        0x00, 0x00, 0x3b, 0x2d, 0x73, 0x67, 0x72 };
#define PAT_MEGALITE_LEN ((long)sizeof (PAT_MEGALITE))

/*****************************************************************************/

/* intro variant 1.50 */
static const unsigned char PAT_V150[]
    = { 0x50, 0xb8, 0x3f, 0x3f, 0xba, 0x3f, 0x3f, 0x05,
        0x00, 0x00, 0x3b, 0x06, 0x02, 0x00, 0x72 };
#define PAT_V150_LEN ((long)sizeof (PAT_V150))

/*****************************************************************************/

/* intro variant un2pack */
static const unsigned char PAT_UN2PACK[]
    = { 0x9c, 0xba, 0x3f, 0x3f, 0x2d, 0x3f, 0x3f, 0x81, 0xe1,
        0x3f, 0x3f, 0x81, 0xf3, 0x3f, 0x3f, 0xb4, 0x3f, 0x3f,
        0xb8, 0x3f, 0x3f, 0xba, 0x3f, 0x3f, 0x8c };
#define PAT_UN2PACK_LEN ((long)sizeof (PAT_UN2PACK))

/*****************************************************************************/

/* intro variant un2pack_corrupt */
static const unsigned char PAT_UN2PACK_CORRUPT[]
    = { 0x9c, 0xba, 0x3f, 0x3f, 0x2d, 0x3f, 0x3f, 0x81,
        0xe1, 0x3f, 0x3f, 0x81, 0xf3, 0x3f, 0x3f, 0xb4 };
#define PAT_UN2PACK_CORRUPT_LEN ((long)sizeof (PAT_UN2PACK_CORRUPT))

/*****************************************************************************/

/* descrambler 1.14 */
static const unsigned char PAT_D114[]
    = { 0x2d, 0x20, 0x00, 0x8e, 0xd0, 0x2d, 0x3f, 0x3f, 0x50, 0x52,
        0xb9, 0x3f, 0x3f, 0xbe, 0x3f, 0x3f, 0x8b, 0xfe, 0xfd, 0x90,
        0x49, 0x74, 0x3f, 0xad, 0x92, 0x33, 0xc2, 0xab, 0xeb, 0xf6 };
#define PAT_D114_LEN ((long)sizeof (PAT_D114))

/*****************************************************************************/

/* descrambler 1.20var1a */
static const unsigned char PAT_D120V1A[]
    = { 0x8b, 0xfc, 0x81, 0xef, 0x3f, 0x3f, 0x57, 0x57, 0x52, 0xb9,
        0x3f, 0x3f, 0xbe, 0x3f, 0x3f, 0x8b, 0xfe, 0xfd, 0x49, 0x74,
        0x3f, 0xad, 0x92, 0x03, 0xc2, 0xab, 0xeb, 0xf6 };
#define PAT_D120V1A_LEN ((long)sizeof (PAT_D120V1A))

/*****************************************************************************/

/* descrambler 1.20var1b */
static const unsigned char PAT_D120V1B[]
    = { 0x8b, 0xfc, 0x81, 0xef, 0x3f, 0x3f, 0x57, 0x57, 0x52, 0xb9,
        0x3f, 0x3f, 0xbe, 0x3f, 0x3f, 0x8b, 0xfe, 0xfd, 0x90, 0x49,
        0x74, 0x3f, 0xad, 0x92, 0x03, 0xc2, 0xab, 0xeb, 0xf6 };
#define PAT_D120V1B_LEN ((long)sizeof (PAT_D120V1B))

/*****************************************************************************/

/* descrambler 1.50 */
static const unsigned char PAT_D150[]
    = { 0x59, 0x2d, 0x20, 0x00, 0x8e, 0xd0, 0x51, 0x3f, 0x3f, 0x00, 0x50, 0x80,
        0x3e, 0x41, 0x01, 0xc3, 0x75, 0xe6, 0x52, 0xb8, 0x3f, 0x3f, 0xbe, 0x3f,
        0x3f, 0x56, 0x56, 0x52, 0x50, 0x90, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f,
        0x3f, 0x74, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0x33 };
#define PAT_D150_LEN ((long)sizeof (PAT_D150))

/*****************************************************************************/

/* descrambler 1.20var2 */
static const unsigned char PAT_D120V2[]
    = { 0x2d, 0x20, 0x00, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f,
        0x3f, 0x3f, 0x3f, 0x3f, 0xb9, 0x3f, 0x3f, 0xbe, 0x3f, 0x3f, 0x3f,
        0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0x74, 0x3f, 0x3f, 0x3f, 0x03 };
#define PAT_D120V2_LEN ((long)sizeof (PAT_D120V2))

/*****************************************************************************/

/* descrambler pkzip2.04clike */
static const unsigned char PAT_DPKZIP204C[]
    = { 0x2d, 0x20, 0x00, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f,
        0x3f, 0x3f, 0x3f, 0x3f, 0xb9, 0x3f, 0x3f, 0xbe, 0x3f, 0x3f, 0x3f,
        0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0x74, 0x3f, 0x3f, 0x3f, 0x03 };
#define PAT_DPKZIP204C_LEN ((long)sizeof (PAT_DPKZIP204C))

/*****************************************************************************/

/* descrambler pklite2.01like */
static const unsigned char PAT_DPKLITE201[]
    = { 0x2d, 0x20, 0x00, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f,
        0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f,
        0xb9, 0x3f, 0x3f, 0xbe, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f,
        0x3f, 0x3f, 0x3f, 0x3f, 0x74, 0x3f, 0x3f, 0x3f, 0x03 };
#define PAT_DPKLITE201_LEN ((long)sizeof (PAT_DPKLITE201))

/*****************************************************************************/

/* descrambler chk4lite2.01like */
static const unsigned char PAT_DCHK4LITE201[]
    = { 0x8b, 0xfc, 0x81, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f,
        0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0xbb, 0x3f, 0x3f, 0xbe, 0x3f, 0x3f,
        0x3f, 0x3f, 0x3f, 0x3f, 0x74, 0x3f, 0x3f, 0x3f, 0x03 };
#define PAT_DCHK4LITE201_LEN ((long)sizeof (PAT_DCHK4LITE201))

/*****************************************************************************/

/* descrambler 1.50beta */
static const unsigned char PAT_D150BETA[]
    = { 0x59, 0x2d, 0x20, 0x00, 0x8e, 0xd0, 0x51, 0x2d, 0x3f, 0x3f,
        0x50, 0x52, 0xb9, 0x3f, 0x3f, 0xbe, 0x3f, 0x3f, 0x8b, 0xfe,
        0xfd, 0x90, 0x49, 0x74, 0x3f, 0xad, 0x92, 0x33 };
#define PAT_D150BETA_LEN ((long)sizeof (PAT_D150BETA))

/*****************************************************************************/

/* clear registers block */
static const unsigned char CLEAR_REGS_PATTERN[15]
    = { 0x33, 0xc0, 0x8b, 0xd8, 0x8b, 0xc8, 0x8b, 0xd0,
        0x8b, 0xe8, 0x8b, 0xf0, 0x8b, 0xf8, 0xcb };

/*****************************************************************************/

/* preserve AX block */
static const unsigned char CLEAR_REGS_REPLACEMENT[15]
    = { 0x33, 0xdb, 0x8b, 0xcb, 0x8b, 0xd3, 0x8b, 0xeb,
        0x8b, 0xf3, 0x8b, 0xfb, 0x8b, 0x07, 0xcb };

/*****************************************************************************/

struct ctx
{
  unsigned char *blob;
  long blob_len;

  int is_win3x;

  long codestart;
  long codeend;
  long entrypoint;
  unsigned ip;

  int beta_exe_structure_known;
  int beta_exe_structure;

  int is_scrambled_known;
  int is_scrambled;

  long position2;
  int position2_known;

  int initial_DX_known;
  unsigned initial_DX;

  int initial_key_known;
  unsigned initial_key;

  const char *descrambler_name;

  long pos_of_scrambled_word_count;
  long scrambled_word_count;
  long pos_of_last_scrambled_word;

  int scrambled_section_startpos_known;
  int scramble_algorithm_known;
  int scramble_algorithm;
};

/*****************************************************************************/

static void
fatal (const char *fmt, ...)
{
  va_list ap;

  (void)fprintf (stderr, "\nERROR: ");
  va_start (ap, fmt);
  (void)vfprintf (stderr, fmt, ap);
  va_end (ap);
  (void)fprintf (stderr, "\n");

  exit (EXIT_FAILURE);
}

/*****************************************************************************/

static unsigned
getbyte (struct ctx const *c, long offset)
{
  if (offset < 0 || offset + 1 > c->blob_len)
    {
      fatal ("Malformed file");
#ifdef __clang_analyzer__
      abort();
#endif
    }

  return c->blob[offset];
}

/*****************************************************************************/

static unsigned
getu16 (struct ctx const *c, long offset)
{
  if (offset < 0 || offset + 2 > c->blob_len)
    {
      fatal ("Malformed file");
#ifdef __clang_analyzer__
      abort();
#endif
    }

  return (unsigned)c->blob[offset] + 256u * (unsigned)c->blob[offset + 1];
}

/*****************************************************************************/

static long
gets16 (struct ctx const *c, long offset)
{
  long val = (long)getu16 (c, offset);

  if (val >= (long)0x8000)
    {
      val -= (long)0x10000;
    }

  return val;
}

/*****************************************************************************/

static void
putu16 (struct ctx *c, unsigned val, long offset)
{
  if (offset < 0 || offset + 2 >= c->blob_len)
    {
      fatal ("Malformed file");
#ifdef __clang_analyzer__
      abort();
#endif
    }

  c->blob[offset]     = (unsigned char)(val % 256u);
  c->blob[offset + 1] = (unsigned char)(val / 256u);
}

/*****************************************************************************/

static long
follow_1byte_jmp (struct ctx const *c, long pos)
{
  return pos + 1 + (long)getbyte (c, pos);
}

/*****************************************************************************/

static long
ip_to_filepos (struct ctx const *c, unsigned ip)
{
  return c->codestart + ((long)ip - (long)0x0100);
}

/*****************************************************************************/

static int
bseq_match (struct ctx const *c, long pos1, const unsigned char *pat,
            long patlen)
{
  long i;

  if (pos1 < 0 || pos1 + patlen > c->blob_len)
    {
      return 0;
    }

  for (i = 0; i < patlen; i++)
    {
      if (pat[i] == 0x3f)
        {
          continue;
        }

      if (c->blob[pos1 + i] != pat[i])
        {
          return 0;
        }
    }

  return 1;
}

/*****************************************************************************/

static int
bseq_exact (struct ctx const *c, long pos1, const unsigned char *pat,
            long patlen)
{
  long i;

  if (pos1 < 0 || pos1 + patlen > c->blob_len)
    {
      return 0;
    }

  for (i = 0; i < patlen; i++)
    {
      if (c->blob[pos1 + i] != pat[i])
        {
          return 0;
        }
    }

  return 1;
}

/*****************************************************************************/

static int
is_win3x_pklite_format (struct ctx const *c)
{
  if (bseq_exact (c, 66, PAT_WIN3_PK1, PAT_WIN3_PK1_LEN))
    {
      return 1;
    }

  if (bseq_exact (c, 66, PAT_WIN3_PK2, PAT_WIN3_PK2_LEN))
    {
      return 1;
    }

  return 0;
}

/*****************************************************************************/

static void
pkl_read_exe (struct ctx *c)
{
  unsigned e_cblp, e_cp, e_cparhdr;
  long cs;

  e_cblp       = getu16 (c, 2);
  e_cp         = getu16 (c, 4);
  e_cparhdr    = getu16 (c, 8);
  c->codestart = (long)e_cparhdr * 16;

  if (e_cblp == 0)
    {
      c->codeend = (long)512 * (long)e_cp;
    }
  else
    {
      c->codeend = (long)512 * ((long)e_cp - 1) + (long)e_cblp;
    }

  c->ip         = getu16 (c, 20);
  cs            = gets16 (c, 22);
  c->entrypoint = c->codestart + 16 * cs + (long)c->ip;

  c->is_win3x = is_win3x_pklite_format (c);

  if (c->codeend > c->blob_len)
    {
      fatal ("Truncated EXE file");
#ifdef __clang_analyzer__
      abort();
#endif
    }
}

/*****************************************************************************/

static void
pkl_decode_intro (struct ctx *c)
{
  int isbeta1 = 0, isbeta2 = 0;
  long pos;
  int intro_found = 0;

  pos = c->entrypoint;

  if (bseq_match (c, pos, PAT_ISBETA1, PAT_ISBETA1_LEN))
    {
      isbeta1 = 1;
    }
  else if (bseq_match (c, pos, PAT_ISBETA2, PAT_ISBETA2_LEN))
    {
      isbeta2 = 1;
    }

  if (c->entrypoint != c->codestart && !isbeta1 && !isbeta2)
    {
      if (bseq_match (c, c->codestart, PAT_SHORT4, PAT_SHORT4_LEN)
       || bseq_match (c, c->codestart, PAT_SHORT5, PAT_SHORT5_LEN))
        {
          pos = c->codestart;
        }
    }

  if (bseq_match (c, pos, PAT_SHORT4, PAT_SHORT4_LEN))
    {
      c->initial_DX_known = 1;
      c->initial_DX       = getu16 (c, pos + 4);
    }
  else if (bseq_match (c, pos, PAT_SHORT5, PAT_SHORT5_LEN))
    {
      c->initial_DX_known = 1;
      c->initial_DX       = getu16 (c, pos + 5);
    }

  if (isbeta1)
    {
      intro_found                 = 1;
      c->beta_exe_structure_known = 1;
      c->beta_exe_structure       = 1;
    }
  else if (isbeta2)
    {
      intro_found                 = 1;
      c->beta_exe_structure_known = 1;
      c->beta_exe_structure       = 1;
    }
  else if (bseq_match (c, pos, PAT_V100, PAT_V100_LEN))
    {
      intro_found           = 1;
      c->is_scrambled_known = 1;
      c->is_scrambled       = 0;
      c->position2_known    = 1;
      c->position2          = pos + 16;
    }
  else if (bseq_match (c, pos, PAT_V112, PAT_V112_LEN))
    {
      intro_found        = 1;
      c->position2_known = 1;
      c->position2       = pos + 15;
    }
  else if (bseq_match (c, pos, PAT_V114, PAT_V114_LEN))
    {
      intro_found        = 1;
      c->position2_known = 1;
      c->position2       = follow_1byte_jmp (c, pos + 14);
    }
  else if (bseq_match (c, pos, PAT_MEGALITE, PAT_MEGALITE_LEN))
    {
      intro_found        = 1;
      c->position2_known = 1;
      c->position2       = follow_1byte_jmp (c, pos + 14);
    }
  else if (bseq_match (c, pos, PAT_V150, PAT_V150_LEN))
    {
      intro_found        = 1;
      c->position2_known = 1;
      c->position2       = follow_1byte_jmp (c, pos + 15);
    }
  else if (bseq_match (c, pos, PAT_UN2PACK, PAT_UN2PACK_LEN))
    {
      intro_found           = 1;
      c->is_scrambled_known = 1;
      c->is_scrambled       = 0;
      c->position2_known    = 1;
      c->position2          = pos + 18 + 16;
    }
  else if (bseq_match (c, pos, PAT_UN2PACK_CORRUPT, PAT_UN2PACK_CORRUPT_LEN))
    {
      intro_found = 1;
    }

  if (!c->initial_key_known && c->initial_DX_known)
    {
      c->initial_key_known = 1;
      c->initial_key       = c->initial_DX;
    }

  if (!intro_found)
    {
      fatal ("Could not find PKLITE stub");
#ifdef __clang_analyzer__
      abort();
#endif
    }

  if (!c->beta_exe_structure_known)
    {
      c->beta_exe_structure_known = 1;
      c->beta_exe_structure       = 0;
    }
}

/*****************************************************************************/

static void
pkl_detect_and_decode_descrambler (struct ctx *c)
{
  long pos;
  int found                = 0;
  long pos_of_endpos_field = 0;
  long pos_of_jmp_field    = 0;
  long op_pos              = 0;

  if (c->beta_exe_structure_known && c->beta_exe_structure)
    {
      c->is_scrambled_known = 1;
      c->is_scrambled       = 0;

      return;
    }

  if (!c->position2_known)
    {
      return;
    }

  if (c->is_scrambled_known && !c->is_scrambled)
    {
      return;
    }

  pos = c->position2;

  if (bseq_match (c, pos, PAT_D114, PAT_D114_LEN))
    {
      c->descrambler_name            = "114";
      c->pos_of_scrambled_word_count = pos + 11;
      pos_of_endpos_field            = pos + 14;
      pos_of_jmp_field               = pos + 22;
      op_pos                         = pos + 25;
      found                          = 1;
    }
  else if (bseq_match (c, pos, PAT_D120V1A, PAT_D120V1A_LEN))
    {
      c->descrambler_name            = "120var1a";
      c->pos_of_scrambled_word_count = pos + 10;
      pos_of_endpos_field            = pos + 13;
      pos_of_jmp_field               = pos + 20;
      op_pos                         = pos + 23;
      found                          = 1;
    }
  else if (bseq_match (c, pos, PAT_D120V1B, PAT_D120V1B_LEN))
    {
      c->descrambler_name            = "120var1b";
      c->pos_of_scrambled_word_count = pos + 10;
      pos_of_endpos_field            = pos + 13;
      pos_of_jmp_field               = pos + 21;
      op_pos                         = pos + 24;
      found                          = 1;
    }
  else if (bseq_match (c, pos, PAT_D150, PAT_D150_LEN))
    {
      c->descrambler_name            = "150";
      c->pos_of_scrambled_word_count = pos + 20;
      pos_of_endpos_field            = pos + 23;
      pos_of_jmp_field               = pos + 38;
      op_pos                         = pos + 45;
      found                          = 1;
    }
  else if (bseq_match (c, pos, PAT_D120V2, PAT_D120V2_LEN))
    {
      c->descrambler_name            = "120var2";
      c->pos_of_scrambled_word_count = pos + 16;
      pos_of_endpos_field            = pos + 19;
      pos_of_jmp_field               = pos + 28;
      op_pos                         = pos + 31;
      found                          = 1;
    }
  else if (bseq_match (c, pos, PAT_DPKZIP204C, PAT_DPKZIP204C_LEN))
    {
      c->descrambler_name            = "pkzip204clike";
      c->pos_of_scrambled_word_count = pos + 16;
      pos_of_endpos_field            = pos + 19;
      pos_of_jmp_field               = pos + 29;
      op_pos                         = pos + 32;
      found                          = 1;
    }
  else if (bseq_match (c, pos, PAT_DPKLITE201, PAT_DPKLITE201_LEN))
    {
      c->descrambler_name            = "pklite201like";
      c->pos_of_scrambled_word_count = pos + 21;
      pos_of_endpos_field            = pos + 24;
      pos_of_jmp_field               = pos + 35;
      op_pos                         = pos + 38;
      found                          = 1;
    }
  else if (bseq_match (c, pos, PAT_DCHK4LITE201, PAT_DCHK4LITE201_LEN))
    {
      c->descrambler_name            = "chk4lite201like";
      c->pos_of_scrambled_word_count = pos + 17;
      pos_of_endpos_field            = pos + 20;
      pos_of_jmp_field               = pos + 27;
      op_pos                         = pos + 30;
      found                          = 1;
    }
  else if (bseq_match (c, pos, PAT_D150BETA, PAT_D150BETA_LEN))
    {
      c->descrambler_name            = "150b";
      c->pos_of_scrambled_word_count = pos + 13;
      pos_of_endpos_field            = pos + 16;
      pos_of_jmp_field               = pos + 24;
      op_pos                         = pos + 27;
      found                          = 1;
    }

  if (found)
    {
      unsigned scrambled_count_raw;
      unsigned scrambled_endpos_raw;

      c->is_scrambled_known = 1;
      c->is_scrambled       = 1;

      scrambled_count_raw = getu16 (c, c->pos_of_scrambled_word_count);

      if (scrambled_count_raw > 0)
        {
          c->scrambled_word_count = (long)scrambled_count_raw - 1;
        }

      scrambled_endpos_raw          = getu16 (c, pos_of_endpos_field);
      c->pos_of_last_scrambled_word = ip_to_filepos (c, scrambled_endpos_raw);

      c->scrambled_section_startpos_known = 1;
      (void)follow_1byte_jmp (c, pos_of_jmp_field);

      if (op_pos > 0)
        {
          unsigned op_byte = getbyte (c, op_pos);

          if (op_byte == 0x33)
            {
              c->scramble_algorithm_known = 1;
              c->scramble_algorithm       = 1;
            }
          else if (op_byte == 0x03)
            {
              c->scramble_algorithm_known = 1;
              c->scramble_algorithm       = 2;
            }
        }
    }
}

/*****************************************************************************/

static void
pkl_descramble (struct ctx *c)
{
  long i, start, stop;
  unsigned n2, val;
  int alg_ADD;

  if (!(c->is_scrambled_known && c->is_scrambled))
    {
      return;
    }

  if (!c->scramble_algorithm_known)
    {
      return;
    }

  if (!c->scrambled_section_startpos_known
    || c->pos_of_last_scrambled_word == 0)
    {
      return;
    }

  if (c->pos_of_scrambled_word_count == 0)
    {
      return;
    }

  if (c->scrambled_word_count < 1)
    {
      return;
    }

  putu16 (c, 0x0001, c->pos_of_scrambled_word_count);

  alg_ADD = (c->scramble_algorithm == 2);

  start = c->pos_of_last_scrambled_word + 2 - (c->scrambled_word_count * 2);
  stop  = c->pos_of_last_scrambled_word + 2;

  for (i = start; i < stop; i += 2)
    {
      unsigned n1 = getu16 (c, i);

      if (i == c->pos_of_last_scrambled_word)
        {
          n2 = c->initial_key;
        }
      else
        {
          n2 = getu16 (c, i + 2);
        }

      if (alg_ADD)
        {
          val = (n1 + n2) & (unsigned)0xFFFF;
        }
      else
        {
          val = n1 ^ n2;
        }

      putu16 (c, val, i);
    }
}

/*****************************************************************************/

static void
read_whole_file (struct ctx *c, const char *filename)
{
  FILE *f;
  long size;

  f = fopen (filename, "rb");

  if (!f)
    {
      fatal ("Could not open '%s' for reading", filename);
#ifdef __clang_analyzer__
      abort();
#endif
    }

  if (fseek (f, 0, SEEK_END) != 0)
    {
      fatal ("Could not seek '%s'", filename);
#ifdef __clang_analyzer__
      abort();
#endif
    }

  size = ftell (f);

  if (size < 0)
    {
      fatal ("Could not determine size of '%s'", filename);
#ifdef __clang_analyzer__
      abort();
#endif
    }

  if (fseek (f, 0, SEEK_SET) != 0)
    {
      fatal ("Could not seek '%s'", filename);
#ifdef __clang_analyzer__
      abort();
#endif
    }

  c->blob = malloc (size > 0 ? (size_t)size : 1);

  if (!c->blob)
    {
      fatal ("Out of memory reading '%s'", filename);
#ifdef __clang_analyzer__
      abort();
#endif
    }

  if (size > 0 && fread (c->blob, 1, (size_t)size, f) != (size_t)size)
    {
      fatal ("Short read on '%s'", filename);
#ifdef __clang_analyzer__
      abort();
#endif
    }

  (void)fclose (f);

  c->blob_len = size;
}

/*****************************************************************************/

static void
run_detection (struct ctx *c, const char *filename)
{
  read_whole_file (c, filename);

  if (c->blob_len < 2
      || !((c->blob[0] == 'M' && c->blob[1] == 'Z')
        || (c->blob[0] == 'Z' && c->blob[1] == 'M')))
    {
      fatal ("Not a DOS EXE file");
#ifdef __clang_analyzer__
      abort();
#endif
    }

  pkl_read_exe (c);

  if (c->is_win3x)
    {
      fatal ("Windows executables not supported");
#ifdef __clang_analyzer__
      abort();
#endif
    }

  pkl_decode_intro (c);
  pkl_detect_and_decode_descrambler (c);

  if (c->is_scrambled_known && c->is_scrambled)
    {
      if (!c->scramble_algorithm_known)
        {
          fatal ("Could not determine scrambling algorithm");
#ifdef __clang_analyzer__
          abort();
#endif
        }

      pkl_descramble (c);
    }
}

/*****************************************************************************/

static long
find_bytes (const unsigned char *hay, long hay_len,
            const unsigned char *needle, long needle_len, long start)
{
  long i;

  for (i = start; i + needle_len <= hay_len; i++)
    {
      if (memcmp (hay + i, needle, (size_t)needle_len) == 0)
        {
          return i;
        }
    }

  return -1;
}

/*****************************************************************************/

static void
apply_clear_regs_fix (struct ctx *c)
{
  long idx, count, p;

  idx = find_bytes (c->blob, c->blob_len, CLEAR_REGS_PATTERN, 15, 0);

  if (idx < 0)
    {
      fatal ("Buggy PKLITE stub not found");
#ifdef __clang_analyzer__
      abort();
#endif
    }

  count = 0;
  p     = 0;

  for (;;)
    {
      p = find_bytes (c->blob, c->blob_len, CLEAR_REGS_PATTERN, 15, p);

      if (p < 0)
        {
          break;
        }

      count++;
      p += 15;
    }

  if (count > 1)
    {
      (void)fprintf (stderr, "Warning: Signature found %ld times\n", count);
    }

  (void)memcpy (c->blob + idx, CLEAR_REGS_REPLACEMENT, 15);
}

/*****************************************************************************/

static void
put_le16 (unsigned char *p, unsigned val)
{
  p[0] = (unsigned char)(val & 0xFF);
  p[1] = (unsigned char)((val >> 8) & 0xFF);
}

/*****************************************************************************/

static unsigned char *
apply_ax_trampoline (struct ctx const *c, long *out_len)
{
  long header_size;
  unsigned orig_e_ip;
  unsigned orig_e_cs_raw;
  long lm_len;
  long trampoline_lm_offset;
  unsigned long new_e_cs;
  unsigned new_e_ip;
  unsigned char trampoline[17];
  int t;
  long new_lm_len;
  unsigned char *new_load_module;
  unsigned e_crlc, e_minalloc, e_maxalloc, e_ss, e_sp, e_lfarlc, e_ovno;
  unsigned e_cparhdr;
  unsigned long new_total_size;
  unsigned e_cp, e_cblp;
  unsigned char header[28];
  long total_out_len;
  unsigned char *out;

  header_size   = c->codestart;
  orig_e_ip     = c->ip;
  orig_e_cs_raw = getu16 (c, 22);

  lm_len               = c->blob_len - header_size;
  trampoline_lm_offset = lm_len;

  new_e_cs = (unsigned long)trampoline_lm_offset / 16;
  new_e_ip = (unsigned)(trampoline_lm_offset % 16);

  if (new_e_cs > (unsigned long)0xFFFF)
    {
      fatal ("File too large: e_cs=%lu needs >16 bits", new_e_cs);
#ifdef __clang_analyzer__
      abort();
#endif
    }

  t = 0;
  trampoline[t++] = 0xa3;
  trampoline[t++] = 0x00;
  trampoline[t++] = 0x00;
  trampoline[t++] = 0x8c;
  trampoline[t++] = 0xc8;
  trampoline[t++] = 0x2d;
  put_le16 (trampoline + t, (unsigned)new_e_cs);
  t += 2;
  trampoline[t++] = 0x05;
  put_le16 (trampoline + t, orig_e_cs_raw);
  t += 2;
  trampoline[t++] = 0x50;
  trampoline[t++] = 0xb8;
  put_le16 (trampoline + t, orig_e_ip);
  t += 2;
  trampoline[t++] = 0x50;
  trampoline[t++] = 0xcb;

  if (t != 17) /* //-V547 */ /* cppcheck-suppress knownConditionTrueFalse */
    {
      fatal ("Trampoline size mismatch");
#ifdef __clang_analyzer__
      abort();
#endif
    }

  new_lm_len      = lm_len + 17;
  new_load_module = malloc ((size_t)new_lm_len);

  if (!new_load_module)
    {
      fatal ("Out of memory");
#ifdef __clang_analyzer__
      abort();
#endif
    }

  (void)memcpy (new_load_module, c->blob + header_size, (size_t)lm_len);
  (void)memcpy (new_load_module + lm_len, trampoline, 17);

  e_crlc     = getu16 (c, 6);
  e_cparhdr  = (unsigned)(header_size / 16);
  e_minalloc = getu16 (c, 10);
  e_maxalloc = getu16 (c, 12);
  e_ss       = getu16 (c, 14);
  e_sp       = getu16 (c, 16);
  e_lfarlc   = getu16 (c, 24);
  e_ovno     = getu16 (c, 26);

  new_total_size = (unsigned long)header_size + (unsigned long)new_lm_len;
  e_cp           = (unsigned)((new_total_size + 511) / 512);
  e_cblp         = (unsigned)(new_total_size % 512);

  header[0] = 'M';
  header[1] = 'Z';
  put_le16 (header + 2, e_cblp);
  put_le16 (header + 4, e_cp);
  put_le16 (header + 6, e_crlc);
  put_le16 (header + 8, e_cparhdr);
  put_le16 (header + 10, e_minalloc);
  put_le16 (header + 12, e_maxalloc);
  put_le16 (header + 14, e_ss);
  put_le16 (header + 16, e_sp);
  put_le16 (header + 18, 0);
  put_le16 (header + 20, new_e_ip);
  put_le16 (header + 22, (unsigned)new_e_cs);
  put_le16 (header + 24, e_lfarlc);
  put_le16 (header + 26, e_ovno);

  total_out_len = header_size + new_lm_len;
  out           = malloc ((size_t)total_out_len);

  if (!out)
    {
      fatal ("Out of memory");
#ifdef __clang_analyzer__
      abort();
#endif
    }

  (void)memcpy (out, header, 28);
  (void)memcpy (out + 28, c->blob + 28, (size_t)(header_size - 28));
  (void)memcpy (out + header_size, new_load_module, (size_t)new_lm_len);

  free (new_load_module);

  *out_len = total_out_len;

  return out;
}

/*****************************************************************************/

static char *
fmt_long (long num)
{
  static char buffers[4][32];
  static int buf_idx = 0;

  char temp[32];
  char *dest = buffers[buf_idx];
  int i, j = 0, count = 0;
  int is_negative = 0;
  unsigned long abs_num;

  buf_idx = (buf_idx + 1) % 4;

  if (num < 0)
    {
      is_negative = 1;
      abs_num     = (unsigned long)(-num);
    } else {
      abs_num = (unsigned long)num;
    }

  do
    {
      temp[j++]  = (char)('0' + (abs_num % 10));
      abs_num   /= 10;
    } while (abs_num > 0);

  i = 0;

  if (is_negative)
    {
      dest[i++] = '-';
    }

  while (j > 0)
    {
      if (count > 0 && j % 3 == 0)
        {
          dest[i++] = ',';
        }

      dest[i++] = temp[--j];
      count++;
    }

  dest[i] = '\0';

  return dest;
}

/*****************************************************************************/

int
main (int argc, char **argv)
{
  struct ctx c;
  unsigned char *patched;
  long patched_len;
  FILE *out_f;

  (void)printf ("PKLAXFIX: PKLITE Executable Postprocessor\n");
  (void)printf ("Copyright (c) 2026");
  (void)printf (" Jeffrey H. Johnson <johnsonjh.dev@gmail.com>\n");

  if (argc != 3)
    {
      (void)fprintf (stderr, "\nUsage: %s input.exe output.exe\n", argv[0]);

      return EXIT_FAILURE;
    }

  (void)memset (&c, 0, sizeof (c));

  run_detection (&c, argv[1]);

  if (c.is_scrambled_known && c.is_scrambled)
    {
      (void)printf ("\nDetected PKLITE extra compression (%s-%s-0x%04x)\n",
                    c.descrambler_name ? c.descrambler_name : "?",
                    (c.scramble_algorithm == 2) ? "ADD" : "XOR",
                    c.initial_key & (unsigned)0xFFFF);
    }
  else
    {
      (void)printf ("\nDetected PKLITE standard compression\n");
    }

  apply_clear_regs_fix (&c);
  patched = apply_ax_trampoline (&c, &patched_len);

  out_f = fopen (argv[2], "wb");

  if (!out_f)
    {
      fatal ("Could not open '%s' for writing", argv[2]);
#ifdef __clang_analyzer__
      abort();
#endif
    }

  if (fwrite (patched, 1, (size_t)patched_len, out_f) != (size_t)patched_len)
    {
      fatal ("Short write on '%s'", argv[2]);
#ifdef __clang_analyzer__
      abort();
#endif
    }

  (void)fclose (out_f);

  (void)printf ("\nWrote '%s' ", argv[2]);
  (void)printf ("(%s bytes in, ", fmt_long (c.blob_len));
  (void)printf ("%s bytes out)\n", fmt_long (patched_len));

  free (patched);
  free (c.blob);

  return EXIT_SUCCESS;
}

/*****************************************************************************/
