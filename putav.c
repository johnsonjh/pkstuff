/*****************************************************************************/

/*
 * PUTAV: Put Authenticity Verification in PKZIP 2.04/2.06
 * Copyright (c) 1994-2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>
 * SPDX-License-Identifer: MIT
 * scspell-id: 82e600c6-b93c-11f1-ada6-80ee73e9b8e7
 */

/*****************************************************************************/

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*****************************************************************************/

#define COMPANY_MAX 52U
#define SERIAL_MAX 16U
#define PATCH_LEN 60U
#define MIDDLE_LEN 52U
#define MARKER_LEN 4U

/*****************************************************************************/

#ifndef PUTAV_DEVICE_BITS
# define PUTAV_DEVICE_BITS 0x81U
#endif

/*****************************************************************************/

static unsigned long
mask32 (unsigned long v)
{
  return v & 0xFFFFFFFFUL;
}

/*****************************************************************************/

static unsigned long
ror32 (unsigned long v, unsigned int n)
{
  v = mask32 (v);
  n &= 31U;

  if (n == 0U)
    {
      return v;
    }

  return mask32 ((v >> n) | (v << (32U - n)));
}

/*****************************************************************************/

static unsigned long
rol32 (unsigned long v, unsigned int n)
{
  v  = mask32 (v);
  n &= 31U;

  if (n == 0U)
    {
      return v;
    }

  return mask32 ((v << n) | (v >> (32U - n)));
}

/*****************************************************************************/

static unsigned long
crc32_byte (unsigned long crc, unsigned int byte)
{
  unsigned int i;

  crc = mask32 (crc ^ (unsigned long)(byte & 0xFFU));

  for (i = 0U; i < 8U; ++i)
    {
      if ((crc & 1UL) != 0UL)
        {
          crc = mask32 ((crc >> 1) ^ 0xEDB88320UL);
        }
      else
        {
          crc = mask32 (crc >> 1);
        }
    }

  return crc;
}

/*****************************************************************************/

static unsigned long
crc32_bytes (unsigned long crc, const unsigned char *p, unsigned int len)
{
  unsigned int i;

  for (i = 0U; i < len; ++i)
    {
      crc = crc32_byte (crc, (unsigned int)p[i]);
    }

  return crc;
}

/*****************************************************************************/

static unsigned long
load32le (const unsigned char *p)
{
  unsigned long v;

  v  = (unsigned long)p[0];
  v |= (unsigned long)p[1] << 8;
  v |= (unsigned long)p[2] << 16;
  v |= (unsigned long)p[3] << 24;

  return mask32 (v);
}

/*****************************************************************************/

static void
store32le (unsigned char *p, unsigned long v)
{
  v    = mask32 (v);
  p[0] = (unsigned char)( v        & 0xFFUL);
  p[1] = (unsigned char)((v >>  8) & 0xFFUL);
  p[2] = (unsigned char)((v >> 16) & 0xFFUL);
  p[3] = (unsigned char)((v >> 24) & 0xFFUL);
}

/*****************************************************************************/

static int
read_line (const char *prompt, unsigned char *buf, unsigned int cap,
           unsigned int *len_out)
{
  char line[256];
  size_t n;

  (void)fputs (prompt, stdout);

  (void)fflush (stdout);

  if (fgets (line, sizeof line, stdin) == NULL)
    {
      return 0;
    }

  n = strlen (line);
  while (n != 0U && (line[n - 1U] == '\n' || line[n - 1U] == '\r'))
    {
      line[n - 1U] = '\0';
      --n;
    }

  if (n > (size_t)cap)
    {
      int ch;

      while ((ch = getchar ()) != EOF && ch != '\n' && ch != '\r');

      return -1;
    }

  if (n != 0U)
    {
      (void)memcpy (buf, line, n);
    }

  buf[n] = '\0';

  *len_out = (unsigned int)n;

  return 1;
}

/*****************************************************************************/

static int
hex_value36 (int c)
{
  if (c >= '0' && c <= '9')
    {
      return c - '0';
    }

  if (c >= 'A' && c <= 'Z')
    {
      return c - 'A' + 10;
    }

  if (c >= 'a' && c <= 'z')
    {
      return c - 'a' + 10;
    }

  return -1;
}

/*****************************************************************************/

static int
parse_serial_line (const char *s, unsigned long *value_out)
{
  const char *p;
  unsigned int count;
  unsigned long value;

  p     = s;
  count = 0U;
  value = 0UL;

  while (*p != '\0')
    {
      int d;

      d = hex_value36 ((unsigned char)*p);

      if (d < 0)
        {
          return 0;
        }

      if (count >= SERIAL_MAX)
        {
          return 0;
        }

      value = mask32 (value * 36UL + (unsigned long)d);
      ++count;
      ++p;
    }

  if (count == 0U)
    {
      return 0;
    }

  *value_out = value;

  return 1;
}

/*****************************************************************************/

static int
read_serial (const char *prompt, unsigned long *value_out)
{
  char line[256];

  for (;;)
    {
      (void)fputs (prompt, stdout);

      (void)fflush (stdout);

      if (fgets (line, sizeof line, stdin) == NULL)
        {
          return 0;
        }

      {
        size_t n;

        n = strlen (line);

        while (n != 0U && (line[n - 1U] == '\n' || line[n - 1U] == '\r'))
          {
            line[n - 1U] = '\0';
            --n;
          }
      }

      if (parse_serial_line (line, value_out))
        {
          return 1;
        }

      (void)fputs ("Invalid serial number.\n", stderr);
    }
}

/*****************************************************************************/

static void
mix_serials (unsigned char s1[4], unsigned char s2[4],
             const unsigned char *name)
{
  unsigned int i;
  unsigned int lane;

  lane = 0U;
  i = 0U;

  while (name[i] != 0U)
    {
      s1[lane] ^= name[i];
      s2[lane] ^= name[i];
      lane      = (lane + 1U) & 3U;
      ++i;
    }
}

/*****************************************************************************/

static void
make_patch (unsigned char patch[PATCH_LEN], const unsigned char *name,
            unsigned int name_len, unsigned long serial1,
            unsigned long serial2)
{
  unsigned char s1[4];
  unsigned char s2[4];
  unsigned char plain[PATCH_LEN];
  unsigned long a;
  unsigned long b;
  unsigned long r;
  unsigned long low1;
  unsigned long low2;
  unsigned int i;
  unsigned int src;
  unsigned char ch;

  store32le (s1, serial1);
  store32le (s2, serial2);

  mix_serials (s1, s2, name);

  a = (load32le (s1) & 0xFFFF0000UL) | (load32le (s2) & 0x0000FFFFUL);
  a = ror32 (a, 15U);
  store32le (plain, a);

  b = (load32le (s2) & 0xFFFF0000UL) | (load32le (s1) & 0x0000FFFFUL);
  b = rol32 (b, 21U);
  store32le (plain + 56U, b);

  low1 = load32le (s1) & 0xFFFFUL;
  low2 = load32le (s2) & 0xFFFFUL;
  r    = mask32 (low1 * low2) & 0xFFFFUL;
  src  = 0U;

  for (i = 0U; i < MIDDLE_LEN; ++i)
    {
      unsigned int slot;

      r    = (r + 0x3F5UL) % 52UL;
      slot = (unsigned int)r;

      if (name_len == 0U)
        {
          ch = 0U;
        }
      else
        {
          ch = name[src];
        }

      plain[4U + slot] =
        (unsigned char)(((unsigned long)PUTAV_DEVICE_BITS
                         + (unsigned long)ch
                         + (unsigned long)slot + 0x7FUL) & 0xFFUL);

      if (name_len == 0U)
        {
          src = 0U;
        }
      else if (src >= name_len)
        {
          src = 0U;
        }
      else
        {
          ++src;
        }
    }

  for (i = 0U; i < PATCH_LEN; ++i)
    {
      patch[i] = (unsigned char)(plain[i] ^ (unsigned char)(PATCH_LEN - i));
    }
}

/*****************************************************************************/

static unsigned long
make_check (const unsigned char *name, unsigned int name_len,
            unsigned long serial1, unsigned long serial2)
{
  unsigned char s1[4];
  unsigned char s2[4];
  unsigned long crc;

  store32le (s1, serial1);
  store32le (s2, serial2);
  mix_serials (s1, s2, name);

  crc = 0xFFFFFFFFUL;
  crc = crc32_bytes (crc, name, name_len);
  crc = crc32_bytes (crc, s1, 4U);
  crc = crc32_bytes (crc, s2, 4U);

  return mask32 (~crc);
}

/*****************************************************************************/

static int
patch_file (const char *filename, const unsigned char patch[PATCH_LEN])
{
  FILE *fp;
  const unsigned char marker[MARKER_LEN] = { 'P', 'K', 't', '0' };
  unsigned int match;
  int c;
  size_t n;

  errno = 0;

  fp = fopen (filename, "r+b");

  if (fp == NULL)
    {
      (void)fprintf (stderr, "\nCan't Open Read/Write: '%s'\n", filename);

      if (errno)
        {
	  (void)fprintf (stderr, "Error: %s\n", strerror(errno));
	}

      return 0;
    }

  match = 0U;

  while ((c = fgetc (fp)) != EOF)
    {
      if (c == (int)marker[match])
        {
          ++match;

          if (match == MARKER_LEN)
            {
              break;
            }
        }
      else
        {
          match = 0U;
        }
    }

  if (match != MARKER_LEN)
    {
      if (ferror (fp))
	{
          (void)fprintf(stderr, "\nError reading: '%s'\n", filename);
	}
      else
	{
          (void)fprintf(stderr, "\nError in: '%s'\n", filename);
        }

      if (errno)
        {
	  (void)fprintf (stderr, "Error: %s\n", strerror(errno));
	}

      (void)fclose (fp);

      return 0;
    }

  if (fseek(fp, 0L, SEEK_CUR) != 0)
    {
      (void)fprintf (stderr, "\nError positioning: '%s'\n", filename);

      if (errno)
        {
	  (void)fprintf (stderr, "Error: %s\n", strerror(errno));
	}

      (void)fclose(fp);

      return 0;
    }

  n = fwrite (patch, 1U, PATCH_LEN, fp);

  if (n != PATCH_LEN)
    {
      (void)fprintf (stderr, "\nError writing: '%s'\n", filename);

      if (errno)
        {
	  (void)fprintf (stderr, "Error: %s\n", strerror(errno));
	}

      (void)fclose (fp);

      return 0;
    }

  if (fclose (fp) != 0)
    {
      (void)fprintf (stderr, "\nError closing: '%s'\n", filename);

      if (errno)
        {
	  (void)fprintf (stderr, "Error: %s\n", strerror(errno));
	}

      return 0;
    }

  return 1;
}

/*****************************************************************************/

int
main (int argc, char **argv)
{
  const char *filename;
  unsigned char name[COMPANY_MAX + 1U];
  unsigned int name_len;
  int rc;
  unsigned long serial1;
  unsigned long serial2;
  unsigned char patch[PATCH_LEN];
  unsigned long check;
  unsigned long uls = (unsigned long)sizeof (unsigned long);

  (void)fprintf (stdout,
    "PUTAV: Put Authenticity Verification in PKZIP 2.04/2.06\n");

  if ((uls * CHAR_BIT) < (unsigned long)32) /* //-V547 */
    {
      (void)fprintf (stderr, "ERROR: unsigned long <32 bits.\n");

      return EXIT_FAILURE;
    }

  if (argc < 2)
    {
      (void)fprintf (stderr, "\nUsage: %s <pkzip.exe>\n", argv[0]);

      return EXIT_FAILURE;
    }
  else
    {
      filename = argv[1];
    }

  (void)printf (
    "\nEnter company name exactly as it "
    "appears on the PKWARE documentation.\n");

  rc = read_line ("Company Name : ", name, COMPANY_MAX, &name_len);

  if (rc <= 0)
    {
      return EXIT_FAILURE;
    }

  (void)printf (
    "\nEnter serial numbers exactly as "
    "they appear on the PKWARE documentation.\n");

  if (!read_serial ("Serial Number 1: ", &serial1))
    {
      return EXIT_FAILURE;
    }

  if (!read_serial ("Serial Number 2: ", &serial2))
    {
      return EXIT_FAILURE;
    }

  (void)fflush (stderr);
  (void)fflush (stdout);

  (void)fprintf (stderr, "\nWorking");

  (void)fflush (stderr);
  (void)fflush (stdout);

  make_patch (patch, name, name_len, serial1, serial2);

  errno = 0;

  if (!patch_file (filename, patch))
    {
      return EXIT_FAILURE;
    }

  check = make_check (name, name_len, serial1, serial2);

  (void)fprintf (stderr, ", done.\n");

  (void)fflush (stderr);

  (void)fprintf (stdout,
    "\nSerial number installation complete.  Check value: %08lx\n",
    mask32 (check));

  return EXIT_SUCCESS;
}

/*****************************************************************************/
