# Classic DOS PKLITE

<!-- toc -->

- [PKLITE 1.x/2.x](#pklite-1x2x)
- [PKLITE notes](#pklite-notes)
  * [Fake PKLite 1.50 (`-e` enabled)](#fake-pklite-150--e-enabled)
  * [Fake PKLITE Professinal 1.20](#fake-pklite-professinal-120)
  * [Other PKLITE versions](#other-pklite-versions)
- [PKLITE utilities](#pklite-utilities)
  * [PKLAXFIX](#pklaxfix)
  * [PKPSPFIX](#pkpspfix)
  * [PKL2FIX](#pkl2fix)
- [Latest known versions](#latest-known-versions)
- [External links](#external-links)

<!-- tocstop -->

## PKLITE 1.x/2.x

The following PKLITE versions are archived here, both in their original form
including documentation and utilities where available, as well as binaries
that have been ***properly*** unpacked, decrypted, and *PSP patched* when
necessary.  The unpacked versions are useful for further reverse engineering
and analysis and also load faster on slow machines (like 8086/8088 systems).

|        Directory | Description           | Version | Date    |
|-----------------:|:----------------------|:--------|:--------|
| [`1.11p`](1.11p) | PKLITE Professional   | 1.11    | 5-15-91 |
| [`1.12p`](1.12p) | PKLITE Professional   | 1.12    | 6-15-91 |
| [`1.13p`](1.13p) | PKLITE Professional   | 1.13    | 8-01-91 |
| [`1.14`](1.14)   | PKLITE Standard       | 1.14    | 6-01-92 |
| [`1.15p`](1.15p) | PKLITE Professional   | 1.15    | 7-30-92 |
| [`1.50`](1.50)   | PKLITE Standard       | 1.50    | 4-10-95 |
| [`1.50f`](1.50f) | PKLITE (**UCF Fake**) | 1.50    | 4-10-95 |
| [`2.01`](2.01)   | PKLITE Standard       | 2.01    | 3-15-96 |

## PKLITE notes

### Fake PKLite 1.50 (`-e` enabled)

* The ***UCF Fake*** **1.50** version is a ***hacked release***,
  *very similar* to the very widely distributed (but ***equally fake***)
  so-called "1.20 Professional" described below.

* The UCF release *does* enable the `-e` option, which *does* change the
  output *just enough* to confuse the official PKLITE `-x` decompressor,
  but it does **not** actually create a "scrambled" decompression stub
  or do any of the other things that the real Professional version would do.

* The fake UCF 1.50 release was encrypted and compressed using a "*warez*"
  *scene*" (**`TEDSUO II [TED/UCF] PaCKeD`**) polymorphic executable packer,
  which I was able to reverse engineer without too much hassle.

#### `TEDSUO II [TED/UCF]` unpacker

* I have included a Python-based [`unpacker`](1.50f/unpacked/ted_unpack.py)
  for it, which is able to decrypt and unpack this `TEDSUO II [TED/UCF]` file
  (and without running any of its code directly).  It is currently specific to
  this file, but if other files are found that use the packer, it would
  possible to create a generic of the unpacking tool.

### Fake PKLITE Professinal 1.20

* After examining ***hundreds*** of PKLITE "1.20 Professional" versions,
  and *every* *single* *one* is the same (fake) 1.12 Professional hack.  You
  can use Jason Summers' [pkla](https://github.com/jsummers/pkla) utility to
  easily identify the fake Professional 1.20 versions by their `-e` output.

* I **will not** be distributing any fake "1.20 Pro" releases here (because
  they are not only misleading but *useless*, because they are essentially
  identical to the *legitimate* 1.12 Pro).

* **It is most likely the real PKLITE "1.20 Professional" was never made
  available as a public release.**

### Other PKLITE versions

* I am not currently interested in collecting, analyzing, or unpacking
  and patching PKLITE releases *older* than 1.11 (unless it's something
  *very* special).  I am actively seeking legitimate releases of PKLITE
  **1.50 Professional** and PKLITE **2.01 Professional**.  If you have a
  copy, please open a
  [GitHub Issue](https://github.com/johnsonjh/pkstuff/issues/new).

## PKLITE utilities

The for *first time*, updated versions of my classic PKLITE utilities are
being released under available under the open source MIT license.

### PKLAXFIX

* The [PKLAXFIX](../../pklaxfix.c) "PKLITE Executable Postprocessor (AX
  restoration fix)" utility fixes a bug present in the generated compressed
  executables of **all** versions of PKLITE before 1.50, where the `AX`
  register was not properly restored after decompression.  Some DOS programs
  depend on the correct behavior to work right.  The current `PKLAXFIX` tool
  has been updated to support fixing "scrambled" and `-e` (extra compression)
  executables.

### PKPSPFIX

* The [PKPSPFIX](../../pkpspfix.c) "PKLITE Executable Postprocessor
  (add PSP protection code)" is an open source utility used to patch
  *decompressed* PKLITE executables that look for a PKLITE
  [PSP signature](http://justsolve.archiveteam.org/wiki/PKLITE#PSP_signature)
  to detect tampering.  Programs can check for the PSP signature in multiple
  places using obfuscated code making manual patching time-consuming.
  `PKPSPFIX` automatically inserts code into the executable to set a
  PSP signature, so no other modifications to the decompressed program are
  needed for it to run correctly.

> [!TIP]
> I ***highly*** recommend decompressing using Jason Summers'
> [`deark`](https://github.com/jsummers/deark) unpacker, which reports if a
> PSP signature is present when decompressing PKLITE packed executables.

### PKL2FIX

> [!WARNING]
> PKLITE 2.01 compressed with are **not compatible** with systems using
> 8086/8088 processors!

* The [PKL2FIX](../../pkl2fix.c) "PKLITE 2.01 Executable Postprocessor" is an
  open source utility that patches PKLITE 2.01 generated compressed
  executables to make them compatible with systems using 8086/8088 CPUs.

## Latest known versions

* The latest known 1.x Professional version is
  [PKLITE Professional 1.15](1.15p).

* The latest known 1.x Standard version is
  [PKLITE Standard 1.50](1.50).

* The latest known 2.x Standard version is
  [PKLITE Standard is 2.01](2.01).

## External links

For more detailed information about PKLITE see:
* [Jason Summers' PKLITE articles](https://entropymine.wordpress.com/tag/pklite/)
* [ModdingWiki PKLITE article](https://moddingwiki.shikadi.net/wiki/PKLite)
* [Just Solve PKLITE article](http://justsolve.archiveteam.org/wiki/PKLITE)
