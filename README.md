<!-- README.md -->
<!-- Copyright (c) 2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com> -->
<!-- SPDX-License-Identifier: MIT -->
<!-- scspell-id: cb21d744-bb70-11f1-b7f4-80ee73e9b8e7 -->
# PKZIP/PKUNZIP/PKSFX/PKLITE utilities

<!-- toc -->

- [Classic DOS PKZIP](#classic-dos-pkzip)
  * [PKZIP 2.04g](#pkzip-204g)
  * [PKZIP 2.06 (IBM)](#pkzip-206-ibm)
  * [PKZIP 2.50](#pkzip-250)
  * [PKZIP utilities](#pkzip-utilities)
    + [Authenticity Verification](#authenticity-verification)
      - [`MAKEAV`](#makeav)
      - [`PUTAV`](#putav)
      - [`pkav_verify.py`](#pkav_verifypy)
      - [PKAV for Info-ZIP](#pkav-for-info-zip)
    + [PKSFX (self-extractor) tools](#pksfx-self-extractor-tools)
      - [`zip2exe_unpack.py`](#zip2exe_unpackpy)
      - [`pksfx_text_tool.py`](#pksfx_text_toolpy)
      - [`pksfx_resource_tool.py`](#pksfx_resource_toolpy)
- [Classic DOS PKLITE](#classic-dos-pklite)
  * [PKLITE 1.x/2.x](#pklite-1x2x)
  * [PKLITE notes](#pklite-notes)
    + [Fake PKLite 1.50 (`-e` enabled)](#fake-pklite-150--e-enabled)
      - [`TEDSUO II [TED/UCF]` unpacker](#tedsuo-ii-teducf-unpacker)
    + [Fake PKLITE Professional 1.20](#fake-pklite-professional-120)
    + [Other PKLITE versions](#other-pklite-versions)
  * [PKLITE utilities](#pklite-utilities)
    + [`PKPSPFIX`](#pkpspfix)
    + [`PKLAXFIX`](#pklaxfix)
    + [`PKL2FIX`](#pkl2fix)
  * [Latest known PKLITE versions](#latest-known-pklite-versions)
- [License](#license)
- [Availability](#availability)
- [External links](#external-links)

<!-- tocstop -->

---

## Classic DOS PKZIP

### PKZIP 2.04g

The latest DOS PKZIP 2.04g releases are archived here, both in their
original forms including documentation and utilities where available, as
well as binaries that have been ***properly*** unpacked, decrypted, and
*PSP patched* when necessary.  The unpacked versions are useful for further
reverse engineering and analysis and also load faster on slow machines
(like 8086/8088 systems).

|                                          Directory | Description              | Date       |
|---------------------------------------------------:|:-------------------------|:-----------|
| [`pkzip/2.04g/docs`](pkzip/2.04g/docs)             | PKZIP 2.04 Documentation | 02‑01‑1993 |
| [`pkzip/2.04g/shareware`](pkzip/2.04g/shareware)   | PKZIP 2.04g Shareware    | 02‑01‑1993 |
| [`pkzip/2.04g/registered`](pkzip/2.04g/registered) | PKZIP 2.04g Registered   | 02‑01‑1993 |

The files in these directories are meant to be *additive* (*or cumulative*):
* The files in the **Documentation** directory apply to
  all PKZIP 2.04g/2.06 versions.
* The files in the **Shareware** directory represent the complete PKZIP
  **2.04g** **Shareware** release.
* The files in the **Registered** directory *replace* the **2.04g**
  **Shareware** files.
* The files in the **IBM Licensed** directory (*see below*) *replace* the
  **2.04g** **Registered** files.

> [!TIP]
> To make a complete DOS PKZIP distribution, first create a directory
> containing all the **Shareware** files, then copy the **Registered** files
> into this same directory.  Make sure that you *overwrite* any files with
> the same name.  If you desire, you can do the same to "upgrade" to the
> **IBM Licensed** 2.06 release, but you should read the following section
> for more details first.

### PKZIP 2.06 (IBM)

|                            Directory | Description                       | Date       |
|-------------------------------------:|:----------------------------------|:-----------|
| [`pkzip/2.06/docs`](pkzip/2.06/docs) | PKZIP **2.06** Documentation      | 01‑24‑1994 |
| [`pkzip/2.06/ibm`](pkzip/2.06/ibm)   | PKZIP **2.06** (**IBM Licensed**) | 01‑24‑1994 |

> [!NOTE]
> The **IBM Licensed** PKZIP 2.06 release is equivalent to the **Registered**
> PKZIP 2.04g, except **it does not contain the encryption features of**
> **2.04g** (so it could be exported and distributed to international IBM
> employees).  There are no other differences known (at this time), so you
> might want to stick with the 2.04g release (certainly if you might ever
> want to create encrypted ZIP archives).

### PKZIP 2.50

The last DOS PKZIP 2.50 release available in original binary form, as well as
***properly*** unpacked, decrypted, and *PSP patched* unpacked executables.

|                                        Directory | Description              | Date       |
|-------------------------------------------------:|:-------------------------|:-----------|
| [`pkzip/2.50/docs`](pkzip/2.50/docs)             | PKZIP 2.50 Documentation | 03‑01‑1999 |
| [`pkzip/2.50/shareware`](pkzip/2.50/shareware)   | PKZIP 2.50 Shareware     | 03‑01‑1999 |
| [`pkzip/2.50/registered`](pkzip/2.50/registered) | PKZIP 2.50 Registered    | 03‑01‑1999 |

> [!WARNING]
> This is the newest (and last) DOS PKZIP release, **2.50**, but unfortunately
> is is **NOT** **recommended for most users**.  It has **known bugs** (and
> subtle issues) when used on vintage machines that have caused much user
> frustration.  You *really* should be using the classic **2.04g**
> (or **2.06**) releases unless you have a **very** **specific** reason
> not to.

### PKZIP utilities

The for *first time*, updated versions of my classic PKZIP utilities are
being made available and distributed under the open source MIT license.

#### Authenticity Verification

After the Authenticity Verification (PKAV) feature of the old PKZIP 1.x was
trivially compromised (see
[40Hex, Number 8, Volume 2, Issue 4, File 3: FindAV v1.5 (July 27 1992)](https://newtotse.com/oldtotse/en/zines/chaos/chaos166.html),
a completely new PKAV system was introduced for PKZIP 2.x.

The new PKAV system was also quickly compromised, with PKAV 2 keygens
appearing in mid‑1993.  PKAV 2 began to be phased out of PKZIP in version 4.0
(which introduced modern cryptography), and support was removed in PKZIP 7.0.

PKAV today is cryptographically useless, but supporting it is *important for
historical preservation and authenticity*, and it unlocks the encrypted AVEXTRA
data present in many original PKZIP archives that would otherwise be completely
inaccessible (or *only* accessible using official PKWARE software).

PKAV is still a fun feature of the classic DOS PKZIP, but no source code or
open implementation was ever released showing how it works, *until now*.

##### `MAKEAV`

* The [`MAKEAV`](makeav.c) "PKZIP 2.04g/2.06/2.50 Authenticity
  Verification Generator" utility is an open source keygen tool that
  generates the two serial numbers needed to enable PKAV for any given
  company name.

##### `PUTAV`

* The [`PUTAV`](putav.c) "PKZIP 2.04g/2.06/2.50 Put Authenticity
  Verification" utility is an open source clone of the PKWARE `PUTAV` utility
  distributed with registered PKZIP releases.  It embeds the PKAV code
  directly into (registered) `PKZIP.EXE` 2.04g/2.06/2.50 executables, enabling
  the use of the `‑!` option.

##### `pkav_verify.py`

* The [`pkav_verify.py`](pkav_verify.py) utility is an open source
  implementation of the PKAV 2.x verification algorithm.  It can verify
  PKAV information in both ZIP files and PKSFX self‑extracting executables.

##### PKAV for Info-ZIP

* [I have added full PKAV support to Info‑ZIP's ZIP, UnZIP, and UnZipSFX.](https://github.com/johnsonjh/infozip-av)

  This support is built on Fedora's current
  [`zip`](https://src.fedoraproject.org/rpms/zip) (`3.0‑46`, 2026‑07‑17),
  [`unzip`](https://src.fedoraproject.org/rpms/unzip) (`6.0‑71`, 2026‑07‑27)
  packages.

  See the [`johnsonjh/infozip‑av`](https://github.com/johnsonjh/infozip-av)
  repository for more information.

#### PKSFX (self-extractor) tools

These utilities help advanced users extract, analyze, and customize the
PKSFX decompression stub.

These tools have a long history, starting out as Pascal programs before
conversion to Python 3 and gaining some features from
[`pkstrings.py`](https://github.com/jsummers/pkla/tree/master/pkstrings).

##### `zip2exe_unpack.py`

* The [`zip2exe_unpack.py`](zip2exe_unpack.py) utility extracts the
  decompression stub from the (de‑PKLITE'd) Registered or Shareware versions
  of `ZIP2EXE.EXE`.

##### `pksfx_text_tool.py`

* The [`pksfx_text_tool.py`](pksfx_text_tool.py) utility can de‑obfuscate
  message blocks in the full (de‑PKLITE'd) PKSFX stub.  You can dump these
  blocks out to disk files for analysis, or de‑obfuscate them *in‑place*
  (in the PKSFX binary itself).  It also disables the de‑obfuscation engine,
  so the patched executable can be easily modified with the de‑obfuscated text
  in place.  This tool supports working with stub that have been reconstructed
  with `pksfx_resource_tool.py`.

##### `pksfx_resource_tool.py`

* The [`pksfx_resource_tool.py`](pksfx_resource_tool.py) utility allows
  analyzing, dumping, and patching of the obfuscated text resources (herald,
  usage, license terms, and registration information) in the full (de‑PKLITE'd)
  PKSFX stub.

## Classic DOS PKLITE

### PKLITE 1.x/2.x

The following PKLITE versions are archived here, both in their original form
including documentation and utilities where available, as well as binaries
that have been ***properly*** unpacked, decrypted, and *PSP patched* when
necessary.  The unpacked versions are useful for further reverse engineering
and analysis and also load faster on slow machines (like 8086/8088 systems).

|                      Directory | Description           | Version | Date       |
|-------------------------------:|:----------------------|:--------|:-----------|
| [`pklite/1.11p`](pklite/1.11p) | PKLITE Professional   | 1.11    | 05‑15‑1991 |
| [`pklite/1.12p`](pklite/1.12p) | PKLITE Professional   | 1.12    | 06‑15‑1991 |
| [`pklite/1.13p`](pklite/1.13p) | PKLITE Professional   | 1.13    | 08‑01‑1991 |
| [`pklite/1.14`](pklite/1.14)   | PKLITE Standard       | 1.14    | 06‑01‑1992 |
| [`pklite/1.15p`](pklite/1.15p) | PKLITE Professional   | 1.15    | 07‑30‑1992 |
| [`pklite/1.50`](pklite/1.50)   | PKLITE Standard       | 1.50    | 04‑10‑1995 |
| [`pklite/1.50f`](pklite/1.50f) | PKLITE (**UCF Fake**) | 1.50    | 04‑10‑1995 |
| [`pklite/2.01`](pklite/2.01)   | PKLITE Standard       | 2.01    | 03‑15‑1996 |

### PKLITE notes

#### Fake PKLite 1.50 (`-e` enabled)

* The ***UCF Fake*** **1.50** version is a ***hacked release***,
  *very similar* to the very widely distributed (but ***equally fake***)
  so‑called "1.20 Professional" described below.

* The UCF release *does* enable the `‑e` option, which *does* change the
  output *just enough* to confuse the official PKLITE `‑x` decompressor,
  but it does **not** actually create a "scrambled" decompression stub
  or do any of the other things that the real Professional version would do.

* The fake UCF 1.50 release was not packed with PKLITE as usual, but was
  instead encrypted and compressed with what seems to be a "*warez scene*"
  (`TEDSUO II [TED/UCF] PaCKeD`) polymorphic executable packer, which was
  reverse engineered to produce unpacked binaries.

##### `TEDSUO II [TED/UCF]` unpacker

* The included a Python‑based [`unpacker`](pklite/1.50f/unpacked/ted_unpack.py)
  is able to decrypt and unpack this `TEDSUO II [TED/UCF]` file, without
  executing any of its code directly.  It is currently specific to this file,
  but if other files are found that use the same packer, it would possible to
  create a generic version of the unpacking tool.

#### Fake PKLITE Professional 1.20

* After examining ***hundreds*** of PKLITE "1.20 Professional" versions,
  *every* *single* *one* was the same (***fake***) hack of PKLITE 1.12
  Professional.  You can use Jason Summers'
  [`pkla.py`](https://github.com/jsummers/pkla) utility to easily identify
  fake PKLITE 1.20 Professional versions by their `‑e` output.

* I **will not** be distributing the fake "1.20 Professional" releases here
  (because it is not just misleading but *useless*, as it is essentially
  identical to the *legitimate* PKLITE 1.12 Professional release). **It is
  most likely the real PKLITE "1.20 Professional" was an internal PKWARE tool
  and was never made available as a public release.**

#### Other PKLITE versions

* I am currently *not interested* in collecting, analyzing, or unpacking
  and patching PKLITE releases *older* than 1.11 (unless it's something
  *very* special).  I am **actively seeking** legitimate releases of PKLITE
  **1.50 Professional** and PKLITE **2.01 Professional**.  If you have a
  copy, please open a
  [GitHub Issue](https://github.com/johnsonjh/pkstuff/issues/new).

### PKLITE utilities

For the *first time*, updated versions of my classic PKLITE utilities are
being released under available under the open source MIT license.

> [!TIP]
> I **highly** recommend Jason Summers'
> [`deark`](https://github.com/jsummers/deark) unpacker for PKLITE
> decompression, since it reports if a PSP signature is present when
> decompressing PKLITE packed executables.

#### `PKPSPFIX`

* The [`PKPSPFIX`](pkpspfix.c) "PKLITE Executable Postprocessor
  (add PSP protection code)" is an open source utility used to patch
  *decompressed* executables (previously compressed with PKLITE) that look for
  a [PSP signature](http://justsolve.archiveteam.org/wiki/PKLITE#PSP_signature)
  to detect unpacking or other tampering.  Because programs can check for the
  PSP signature in multiple places using obfuscated code, manual patching
  can be tedious.  `PKPSPFIX` automatically inserts code into the unpacked
  executable to set the PSP signature, so no other modifications to the
  program are needed for it to run correctly.

#### `PKLAXFIX`

* The [`PKLAXFIX`](pklaxfix.c) "PKLITE Executable Postprocessor (AX
  restoration fix)" utility fixes a bug present in the generated *compressed*
  executables of **all** versions of PKLITE *before 1.50*, where the `AX`
  register was not properly restored after decompression.  Some DOS programs
  depend on the correct AX register status to work correctly.  The current
  `PKLAXFIX` tool has been updated to support fixing "scrambled" and `‑e`
  (extra compression) executables.

#### `PKL2FIX`

* The [`PKL2FIX`](../pkl2fix.c) "PKLITE 2.01 Executable Postprocessor" is an
  open source utility that patches PKLITE 2.01 generated compressed
  executables to make them compatible with systems using 8086/8088 CPUs.

### Latest known PKLITE versions

* The latest known **1.x Professional** version is
  [PKLITE Professional 1.15](1.15p).
* The latest known **1.x Standard** version is
  [PKLITE Standard 1.50](1.50).
* The latest known **2.x Standard** version is
  [PKLITE Standard 2.01](2.01).

## License

* All original programs and source code in this repository are distributed
  under the terms of the [MIT License](LICENSE).
* All programs by other authors are included strictly for the convenience
  of historical researchers.  We make no copyright claims on them and they
  remain the property of their respective owners.

## Availability

* [https://github.com/johnsonjh/pkstuff](https://github.com/johnsonjh/pkstuff)
* [https://gitlab.com/johnsonjh/pkstuff](https://gitlab.com/johnsonjh/pkstuff)

## External links

* [Common ZIP specification](https://commonzip.org/)
* [Jason Summers' `deark`](https://github.com/jsummers/deark)
* [Jason Summers' `pkla.py`](https://github.com/jsummers/pkla)
* [Jason Summers' PKLITE articles](https://entropymine.wordpress.com/tag/pklite/)
* [Jason Summers' `pkstrings.py`](https://github.com/jsummers/pkla/tree/master/pkstrings)
* [Jason Summers' ZIP articles](https://entropymine.wordpress.com/tag/zip/)
* [Just Solve PKLITE article](http://justsolve.archiveteam.org/wiki/PKLITE)
* [Just Solve PKZIP article](http://justsolve.archiveteam.org/wiki/PKZIP)
* [ModdingWiki PKLITE article](https://moddingwiki.shikadi.net/wiki/PKLite)
* [PCjs PKZIP History article](https://www.pcjs.org/blog/2025/04/05/)
* [PKAV‑enabled Info‑ZIP](https://github.com/johnsonjh/infozip-av)
