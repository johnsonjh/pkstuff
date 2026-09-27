# PKLITE

The following PKLITE versions are archived here, both in their original form
including documentation and utilities where available, as well as binaries
that have been ***properly*** unpacked, decrypted, and *PSP patched* when
necessary.  The unpacked versions are useful for further reverse engineering
and analysis and also load faster on slow machines (like 8086/8088 systems).

|        Directory | Description         | Version | Date    |
|-----------------:|:--------------------|:--------|:--------|
| [`1.11p`](1.11p) | PKLITE Professional | 1.11    | 5-15-91 |
| [`1.12p`](1.12p) | PKLITE Professional | 1.12    | 6-15-91 |
| [`1.13p`](1.13p) | PKLITE Professional | 1.13    | 8-01-91 |
| [`1.14`](1.14)   | PKLITE Standard     | 1.14    | 6-01-92 |
| [`1.15p`](1.15p) | PKLITE Professional | 1.15    | 7-30-92 |
| [`1.50`](1.50)   | PKLITE Standard     | 1.50    | 4-10-95 |
| [`1.50f`](1.50f) | PKLITE (*UCF Fake*) | 1.50    | 4-10-95 |
| [`2.01`](2.01)   | PKLITE Standard     | 2.01    | 3-15-96 |

## PKLITE Notes

### Fake PKLite 1.50 (`-e` enabled)

* The ***UCF Fake*** **1.50** version is a hacked release, *very similar* to
  the very widely distributed (but ***equally fake***) so-called
  "*1.20 Professional*" version, we describe in the next section.
* The UCF release *does* enable the `-e` option, and it does change the
  output just enough to confuse the `-x` decompression option, but it does
  **not** actually create a "scrambled" decompression stub or do any of the
  other things that the real Professional version do.
* The fake UCF 1.50 release was encrypted and compressed using a *warez scene*
  (`TEDSUO II [TED/UCF] PaCKeD`) polymorphic executable packer (which I was
  able to reverse engineer without *too* much hassle).  I have included a
  Python-based [`unpacker`](1.50f/unpacked/ted_unpack.py), which is specific
  to this file.  If other files are found that use this same packer, it should
  be possible to create a generic version of this unpacking tool.

### Fake PKLITE Pro 1.20

* NOTE: I have examined *hundreds* of PKLITE "*1.20 Professional*" versions,
  and *every* *single* *one* is the same (fake) 1.12 Pro hack.  You can use
  Jason Summers' [pkla](https://github.com/jsummers/pkla) utility to easily
  identify the fake Pro versions by their `-e` output.
* I **will not** be distributing any fake 1.20 Pro releases here (because they
  are misleading and also *useless*, because they are essentially identical
  to the legitimate 1.12 Pro).

## Latest versions

* The latest known 1.x version of [PKLITE Professional is 1.15](1.15p).

* The latest known 1.x version of [PKLITE Standard is 1.50](1.50).

* The latest known 2.x version of [PKLITE Standard is 2.01](2.01).

## External links

* For more detailed information about PKLITE see
  [Jason Summers' PKLITE articles](https://entropymine.wordpress.com/tag/pklite/),
  the [ModdingWiki PKLITE article](https://moddingwiki.shikadi.net/wiki/PKLite),
  and the [Just Solve PKLITE article](http://justsolve.archiveteam.org/wiki/PKLITE).
