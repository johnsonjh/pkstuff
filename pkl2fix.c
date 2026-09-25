/*****************************************************************************/

/*
 * PKL2FIX: PKLITE 2.01 Executable Postprocessor (8086/8088 compatibility)
 * Copyright (c) 1996-2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>
 * SPDX-License-Identifer: MIT
 * scspell-id: 73bf7bea-b88d-11f1-87b1-80ee73e9b8e7
 */

/*****************************************************************************/

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*****************************************************************************/

struct PatchTarget
{
  const char *name;
  const unsigned char *target;
  const unsigned char *replacement;
  size_t length;
};

/*****************************************************************************/

int
main (int argc, char **argv)
{
  const char *input_path;
  const char *output_path;
  FILE *fin = NULL;
  FILE *fout = NULL; /* cppcheck-suppress variableScope */
  unsigned char *buffer = NULL;
  long file_size;
  size_t bytes_read;
  int patches_applied = 0;
  size_t i;

  const unsigned char std_small_bound_tgt[]
      = { 0x50, 0x62, 0xEB, 0xAE };

  const unsigned char std_small_bound_pch[]
      = { 0x50, 0x90, 0x90, 0x90 };

  const unsigned char std_small_0f_tgt[]
      = { 0x0F, 0xFD, 0xFE, 0xF3 };

  const unsigned char std_small_0f_pch[]
      = { 0x90, 0x90, 0xFE, 0xF3 };

  const unsigned char std_large_c1_1_tgt[]
      = { 0xC5, 0x8E, 0xDD, 0x8B, 0xC1, 0x33, 0xDB };

  const unsigned char std_large_c1_1_pch[]
      = { 0xC5, 0x8E, 0xDD, 0x8B, 0x90, 0x90, 0x90 };

  const unsigned char std_large_c1_2_tgt[]
      = { 0x83, 0x00, 0x00, 0xC1, 0x0C, 0x56, 0x8C };

  const unsigned char std_large_c1_2_pch[]
      = { 0x83, 0x00, 0x00, 0x90, 0x90, 0x90, 0x8C };

  const unsigned char crc_small_chk_tgt[]
      = { 0x3D, 0xCB, 0x6C, 0x74, 0x21 };

  const unsigned char crc_small_chk_pch[]
      = { 0x3D, 0xCB, 0x6C, 0xEB, 0x21 };

  const unsigned char crc_large_chk_tgt[]
      = { 0x3D, 0xE4, 0x9A, 0x74, 0x21 };

  const unsigned char crc_large_chk_pch[]
      = { 0x3D, 0xE4, 0x9A, 0xEB, 0x21 };

  struct PatchTarget targets[6];

  targets[0].name        = "Standard Small (BOUND)";
  targets[0].target      = std_small_bound_tgt;
  targets[0].replacement = std_small_bound_pch;
  targets[0].length      = sizeof (std_small_bound_tgt);

  targets[1].name        = "Standard Small (0F Extension)";
  targets[1].target      = std_small_0f_tgt;
  targets[1].replacement = std_small_0f_pch;
  targets[1].length      = sizeof (std_small_0f_tgt);

  targets[2].name        = "Standard Large (First C1 Shift)";
  targets[2].target      = std_large_c1_1_tgt;
  targets[2].replacement = std_large_c1_1_pch;
  targets[2].length      = sizeof (std_large_c1_1_tgt);

  targets[3].name        = "Standard Large (Tail C1 Loop)";
  targets[3].target      = std_large_c1_2_tgt;
  targets[3].replacement = std_large_c1_2_pch;
  targets[3].length      = sizeof (std_large_c1_2_tgt);

  targets[4].name        = "CRC Small (Integrity Bypass)";
  targets[4].target      = crc_small_chk_tgt;
  targets[4].replacement = crc_small_chk_pch;
  targets[4].length      = sizeof (crc_small_chk_tgt);

  targets[5].name        = "CRC Large (Integrity Bypass)";
  targets[5].target      = crc_large_chk_tgt;
  targets[5].replacement = crc_large_chk_pch;
  targets[5].length      = sizeof (crc_large_chk_tgt);

  (void)fprintf (stdout,
    "PKL2FIX: PKLITE 2.01 Executable Postprocessor "
    "(8086/8088 compatibility)\n");

  if (argc < 3)
    {
      (void)fprintf (stdout,
        "Usage: %s <input.exe> <output.exe>\n", argv[0]);

      return 1;
    }

  input_path = argv[1];
  output_path = argv[2];

  fin = fopen (input_path, "rb");

  if (!fin)
    {
      (void)fprintf (stderr,
        "[!] Error: Input file '%s' does not exist or cannot be opened.\n",
        input_path);

      return 1;
    }

  if (fseek (fin, 0, SEEK_END) != 0)
    {
      (void)fprintf (stderr,
        "[!] Error: Failed seeking inside input file stream.\n");

      (void)fclose (fin);

      return 1;
    }

  file_size = ftell (fin);

  if (file_size < 0)
    {
      (void)fprintf (stderr, "[!] Error: Invalid file sizing readout map.\n");

      (void)fclose (fin);

      return 1;
    }

  rewind (fin);

  if (file_size < 0x40)
    {
      if (errno)
        {
          errno = 0;
        }

      (void)fprintf (stderr,
         "[!] Error: File size too small to contain a valid DOS "
         "executable header footprint.\n");

      (void)fclose (fin);

      return 1;
    }

  if (errno)
    {
      errno = 0;
    }

  buffer = (unsigned char *)malloc ((size_t)file_size);


  if (!buffer)
    {
      if (errno)
        {
          errno = 0;
        }

      (void)fprintf (stderr,
        "[!] Error: Memory allocation failure allocating "
        "allocation payload buffer map.\n");

      (void)fclose (fin);

      return 1;
    }

  bytes_read = fread (buffer, 1, (size_t)file_size, fin);

  (void)fclose (fin);

  if (bytes_read < (size_t)file_size)
    {
      (void)fprintf (stderr,
        "[!] Error: Truncated stream reading input file payload.\n");

      (void)free (buffer);

      return 1;
    }

  if (buffer[0] != 'M' || buffer[1] != 'Z')
    {
      (void)fprintf (stderr,
        "[!] Error: File does not appear to contain a valid "
        "DOS MZ executable map marker.\n");

      free (buffer);

      return 1;
    }

  (void)fprintf (stdout,
    "[*] Analyzing '%s' (%ld bytes)...\n", input_path, file_size);

  for (i = 0; i < 6; i++)
    {
      size_t scan_limit, j;
      size_t match_len = targets[i].length;

      if ((size_t)file_size < match_len)
        {
          continue;
        }

      scan_limit = (size_t)file_size - match_len + 1;

      for (j = 0; j < scan_limit; j++)
        {
          if (memcmp (&buffer[j], targets[i].target, match_len) == 0)
            {
              (void)memcpy (&buffer[j], targets[i].replacement, match_len);
              (void)fprintf (stdout,
                "    [%c] Found: %s at file offset location: 0x%04lX\n",
                (i < 2 ? 'A' : (i < 4 ? 'B' : (i == 4 ? 'C' : 'D'))),
                targets[i].name, (unsigned long)j);

              patches_applied++;
            }
        }
    }

  if (patches_applied > 0)
    {
      fout = fopen (output_path, "wb");

      if (!fout)
        {
          (void)fprintf (stderr,
            "[!] Error: Output '%s' cannot be created/opened for writing.\n",
            output_path);

          free (buffer);

          return 1;
        }

      if (fwrite (buffer, 1, (size_t)file_size, fout) < (size_t)file_size)
        {
          (void)fprintf (stderr,
            "[!] Error: Truncated stream event when writing payload.\n");
          (void)fclose (fout);

          free (buffer);

          return 1;
        }

      (void)fclose (fout);

      (void)fprintf (stdout,
        "[!] Success: Applied %d patches to the destination file.\n",
        patches_applied);
      (void)fprintf (stdout,
        "[!] Wrote 8088-compatible output to '%s'\n", output_path);
    }
  else
    {
      (void)fprintf (stdout,
        "[-] No patches applied! No match or already patched?\n");
    }

  free (buffer);

  return 0;
}

/*****************************************************************************/
