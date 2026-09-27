/*****************************************************************************/

/*
 * PKPSPFIX: PKLITE Executable Postprocessor (add PSP protection code)
 * Copyright (c) 1993-2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>
 * Copyright (c) 2023-2026 Jason Summers <jason1@pobox.com>
 * SPDX-License-Identifer: MIT
 * scspell-id: 548da6f8-ba35-11f1-b565-80ee73e9b8e7
 */

/*****************************************************************************/

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*****************************************************************************/

#define MZ_MIN_HEADER_SIZE 28U
#define MZ_OFF_CBLP 2U
#define MZ_OFF_CP 4U
#define MZ_OFF_CPARHDR 8U
#define MZ_OFF_CSUM 18U
#define MZ_OFF_IP 20U
#define MZ_OFF_CS 22U
#define MZ_OFF_OVNO 26U

/*****************************************************************************/

#define PSP_SIG_OFFSET 0x005cU

/*****************************************************************************/

#define STUB_CODE_SIZE 32U
#define STUB_TARGET_PTR_OFF 32U
#define STUB_TARGET_SEG_OFF 34U
#define STUB_SAVE_BX_OFF 36U
#define STUB_SIZE 38U

/*****************************************************************************/

static unsigned
get_le16 (const unsigned char *p)
{
  return (unsigned)p[0] | ((unsigned)p[1] << 8);
}

/*****************************************************************************/

static void
put_le16 (unsigned char *p, unsigned v)
{
  p[0] = (unsigned char)(v & 0xffU);
  p[1] = (unsigned char)((v >> 8) & 0xffU);
}

/*****************************************************************************/

static unsigned long
mz_declared_size (const unsigned char *buf)
{
  unsigned cblp;
  unsigned cp;

  cblp = get_le16 (buf + MZ_OFF_CBLP);
  cp = get_le16 (buf + MZ_OFF_CP);

  if (cp == 0U || cblp > 511U)
    {
      return 0UL;
    }

  if (cblp == 0U)
    {
      return (unsigned long)cp * 512UL;
    }

  return ((unsigned long)cp - 1UL) * 512UL + (unsigned long)cblp;
}

/*****************************************************************************/

static unsigned
mz_checksum (unsigned char *buf, unsigned long len)
{
  unsigned long i;
  unsigned long sum;

  buf[MZ_OFF_CSUM] = 0;
  buf[MZ_OFF_CSUM + 1] = 0;

  sum = 0UL;
  i = 0UL;

  while (i < len)
    {
      unsigned word;

      word = (unsigned)buf[i];

      if (i + 1UL < len)
        {
          word |= (unsigned)buf[i + 1UL] << 8;
        }

      sum = (sum + (unsigned long)word) & 0xffffUL;
      i += 2UL;
    }

  return (unsigned)((~sum) & 0xffffUL);
}

/*****************************************************************************/

static int
read_file (const char *name, unsigned char **pbuf, long *plen)
{
  FILE *f;
  long len;
  unsigned char *buf;

  *pbuf = NULL;
  *plen = 0L;

  f = fopen (name, "rb");

  if (!f)
    {
      (void)fprintf (stderr, "[!] Cannot open '%s' for reading.\n", name);

      return 0;
    }

  if (fseek (f, 0L, SEEK_END) != 0)
    {
      (void)fprintf (stderr, "[!] Cannot seek in '%s'.\n", name);
      (void)fclose (f);

      return 0;
    }

  len = ftell (f);

  if (len < 0L)
    {
      (void)fprintf (stderr, "[!] Cannot determine size of '%s'.\n", name);
      (void)fclose (f);

      return 0;
    }

  if (fseek (f, 0L, SEEK_SET) != 0)
    {
      (void)fprintf (stderr, "[!] Cannot rewind '%s'.\n", name);
      (void)fclose (f);

      return 0;
    }

  buf = (unsigned char *)malloc (len > 0L ? (size_t)len : (size_t)1);

  if (!buf)
    {
      (void)fprintf (stderr, "[!] Out of memory reading '%s'.\n", name);
      (void)fclose (f);

      return 0;
    }

  if (len > 0L && fread (buf, 1, (size_t)len, f) != (size_t)len)
    {
      (void)fprintf (stderr, "[!] Short read from '%s'.\n", name);
      free (buf);
      (void)fclose (f);

      return 0;
    }

  if (fclose (f) != 0)
    {
      (void)fprintf (stderr, "[!] Error closing '%s' after reading.\n", name);
      free (buf);

      return 0;
    }

  *pbuf = buf;
  *plen = len;

  return 1;
}

/*****************************************************************************/

static int
write_file (const char *name, const unsigned char *buf, long len)
{
  FILE *f;

  f = fopen (name, "wb");

  if (!f)
    {
      (void)fprintf (stderr, "[!] Cannot open '%s' for writing.\n", name);

      return 0;
    }

  if (len > 0L && fwrite (buf, 1, (size_t)len, f) != (size_t)len)
    {
      (void)fprintf (stderr, "[!] Short write to '%s'.\n", name);
      (void)fclose (f);

      return 0;
    }

  if (fclose (f) != 0)
    {
      (void)fprintf (stderr, "[!] Error closing '%s' after writing.\n", name);

      return 0;
    }

  return 1;
}

/*****************************************************************************/

static int
build_stub (unsigned char *stub, const char *sig, unsigned orig_ip,
            unsigned orig_cs, unsigned new_ip, unsigned new_cs)
{
  unsigned target_ptr;
  unsigned target_seg;
  unsigned save_bx;
  unsigned delta;
  unsigned t;

  target_ptr = new_ip + STUB_TARGET_PTR_OFF;
  target_seg = new_ip + STUB_TARGET_SEG_OFF;
  save_bx = new_ip + STUB_SAVE_BX_OFF;
  delta
      = (unsigned)(((unsigned long)orig_cs + 0x10000UL - (unsigned long)new_cs)
                   & 0xffffUL);

  t = 0U;

  /* mov word ptr [005Ch], imm16 -- DS is the PSP at EXE entry. */
  stub[t++] = 0xc7;
  stub[t++] = 0x06;
  put_le16 (stub + t, PSP_SIG_OFFSET);
  t += 2U;
  stub[t++] = (unsigned char)sig[0];
  stub[t++] = (unsigned char)sig[1];

  /* mov cs:[save_bx], bx */
  stub[t++] = 0x2e;
  stub[t++] = 0x89;
  stub[t++] = 0x1e;
  put_le16 (stub + t, save_bx);
  t += 2U;

  /* mov bx, cs */
  stub[t++] = 0x8c;
  stub[t++] = 0xcb;

  /* lea bx, [bx+delta] -- computes relocated original CS, flags unchanged. */
  stub[t++] = 0x8d;
  stub[t++] = 0x9f;
  put_le16 (stub + t, delta);
  t += 2U;

  /* mov cs:[target_seg], bx */
  stub[t++] = 0x2e;
  stub[t++] = 0x89;
  stub[t++] = 0x1e;
  put_le16 (stub + t, target_seg);
  t += 2U;

  /* mov bx, cs:[save_bx] */
  stub[t++] = 0x2e;
  stub[t++] = 0x8b;
  stub[t++] = 0x1e;
  put_le16 (stub + t, save_bx);
  t += 2U;

  /* jmp far ptr cs:[target_ptr] */
  stub[t++] = 0x2e;
  stub[t++] = 0xff;
  stub[t++] = 0x2e;
  put_le16 (stub + t, target_ptr);
  t += 2U;

  /* Runtime far-jump pointer: IP is fixed, CS is filled in by the stub. */
  put_le16 (stub + STUB_TARGET_PTR_OFF, orig_ip);
  put_le16 (stub + STUB_TARGET_SEG_OFF, 0U);
  put_le16 (stub + STUB_SAVE_BX_OFF, 0U);

  return 1;
}

/*****************************************************************************/

int
main (int argc, char **argv)
{
  const char *sig;
  const char *input_name;
  const char *output_name;
  unsigned char *input;
  unsigned char *output;
  unsigned char stub[STUB_SIZE];
  long input_len;
  long output_len;
  unsigned long declared_size;
  unsigned long header_size;
  unsigned long load_size;
  unsigned long new_size;
  unsigned long new_cs_ul;
  unsigned orig_ip;
  unsigned orig_cs;
  unsigned old_checksum;
  unsigned new_ip;
  unsigned new_cs;
  unsigned new_cp;
  unsigned new_cblp;
  unsigned new_checksum;

  (void)printf ("\nPKSPSPIX:");
  (void)printf (" PKLITE Executable Postprocessor");
  (void)printf (" (add PSP protection code)\n");
  (void)printf ("Copyright (c) 1994-2026");
  (void)printf (" Jeffrey H. Johnson <johnsonjh.dev@gmail.com>\n");
  (void)printf ("Copyright (c) 2023-2026 Jason Summers <jason1@pobox.com>\n");
  (void)printf ("Source available: https://github.com/johnsonjh/pkstuff/\n\n");

  if (argc != 4)
    {
      (void)fprintf (stderr, "Usage: %s <code> <input.exe> <output.exe>\n",
                     argv[0]);
      (void)fprintf (stderr, "Note: Code is 2 alphabetic characters,");
      (void)fprintf (stderr, " usually \"pk\" or \"PK\".\n");

      return EXIT_FAILURE;
    }

  sig = argv[1];
  input_name = argv[2];
  output_name = argv[3];

  if (strlen (sig) != 2U)
    {
      (void)fprintf (stderr,
          "[!] Signature must be two bytes (e.g., \"PK\" or \"pk\").\n");

      return EXIT_FAILURE;
    }

  input = NULL;
  input_len = 0L;

  if (!read_file (input_name, &input, &input_len))
    {
      return EXIT_FAILURE;
    }

  if (input_len < (long)MZ_MIN_HEADER_SIZE)
    {
      (void)fprintf (stderr, "[!] Input too small to be a DOS executable.\n");
      free (input);

      return EXIT_FAILURE;
    }

  if (!((input[0] == 'M' && input[1] == 'Z')
        || (input[0] == 'Z' && input[1] == 'M')))
    {
      (void)fprintf (stderr, "[!] Input not a DOS executable.\n");
      free (input);

      return EXIT_FAILURE;
    }

  header_size = (unsigned long)get_le16 (input + MZ_OFF_CPARHDR) * 16UL;

  if (header_size < (unsigned long)MZ_MIN_HEADER_SIZE
      || header_size > (unsigned long)input_len)
    {
      (void)fprintf (stderr, "[!] Invalid DOS MZ header size.\n");
      free (input);

      return EXIT_FAILURE;
    }

  declared_size = mz_declared_size (input);

  if (declared_size == 0UL)
    {
      (void)fprintf (stderr, "[!] Invalid MZ page-size fields.\n");
      free (input);

      return EXIT_FAILURE;
    }

  if (declared_size != (unsigned long)input_len)
    {
      (void)fprintf (stderr,
          "[!] MZ-header size (%lu) differs from actual size (%ld).\n",
          declared_size, input_len);
      (void)fprintf (stderr, "    This file cannot be processed, aborting.\n");
      free (input);

      return EXIT_FAILURE;
    }

  if (get_le16 (input + MZ_OFF_OVNO) != 0U)
    {
      (void)fprintf (stderr,
          "[!] Overlay executables (e_ovno != 0) are not supported.\n");
      free (input);

      return EXIT_FAILURE;
    }

  load_size = (unsigned long)input_len - header_size;
  new_cs_ul = load_size / 16UL;
  new_ip = (unsigned)(load_size % 16UL);

  if (new_cs_ul > 0xffffUL)
    {
      (void)fprintf (stderr,
          "[!] Load module too large for 16-bit wrapped CS value.\n");
      free (input);

      return EXIT_FAILURE;
    }

  new_cs = (unsigned)new_cs_ul;

  if (input_len > LONG_MAX - (long)STUB_SIZE)
    {
      (void)fprintf (stderr, "[!] Output size overflowed file size limits.\n");
      free (input);

      return EXIT_FAILURE;
    }

  output_len = input_len + (long)STUB_SIZE;
  new_size = (unsigned long)output_len;

  if (((new_size + 511UL) / 512UL) > 0xffffUL)
    {
      (void)fprintf (stderr, "[!] Output too large for MZ e_cp.\n");
      free (input);

      return EXIT_FAILURE;
    }

  orig_ip = get_le16 (input + MZ_OFF_IP);
  orig_cs = get_le16 (input + MZ_OFF_CS);
  old_checksum = get_le16 (input + MZ_OFF_CSUM);

  if (!build_stub (stub, sig, orig_ip, orig_cs, new_ip, new_cs))
    {
      (void)fprintf (stderr, "[!] Internal wrapper size error.\n");
      free (input);

      return EXIT_FAILURE;
    }

  output = (unsigned char *)malloc ((size_t)output_len);

  if (!output)
    {
      (void)fprintf (stderr, "[!] Out of memory processing file.\n");
      free (input);

      return EXIT_FAILURE;
    }

  (void)memcpy (output, input, (size_t)input_len);
  (void)memcpy (output + input_len, stub, (size_t)STUB_SIZE);

  new_cp = (unsigned)((new_size + 511UL) / 512UL);
  new_cblp = (unsigned)(new_size % 512UL);

  put_le16 (output + MZ_OFF_CBLP, new_cblp);
  put_le16 (output + MZ_OFF_CP, new_cp);
  put_le16 (output + MZ_OFF_IP, new_ip);
  put_le16 (output + MZ_OFF_CS, new_cs);

  if (old_checksum != 0U)
    {
      new_checksum = mz_checksum (output, new_size);
      put_le16 (output + MZ_OFF_CSUM, new_checksum);
    }
  else
    {
      put_le16 (output + MZ_OFF_CSUM, 0U);
      new_checksum = 0U;
    }

  if (!write_file (output_name, output, output_len))
    {
      free (output);
      free (input);

      return EXIT_FAILURE;
    }

  (void)printf ("[*] PSP signature  : \"%c%c\" -> DS:005Ch\n", sig[0], sig[1]);
  (void)printf ("[*] Original entry : %04X:%04X\n", orig_cs, orig_ip);
  (void)printf ("[*] Wrapper entry  : %04X:%04X\n", new_cs, new_ip);
  (void)printf ("[*] Wrapper size   : %u bytes\n", (unsigned)STUB_SIZE);

  if (old_checksum != 0U)
    {
      (void)printf ("[*] MZ checksum:    %04X -> %04X\n", old_checksum,
                    new_checksum);
    }

  (void)printf ("[+] Wrote '%s' (%ld bytes) successfully.\n",
                output_name, output_len);

  free (output);
  free (input);

  return EXIT_SUCCESS;
}

/*****************************************************************************/
