# PKSFX Tools

These utilities help advanced users extract, analyze, and customize the
`PKSFX` decompression stub.

These tools have a long history, starting out as Pascal programs before
conversion to Python and gaining some features from
[`pkstrings.py`](https://github.com/jsummers/pkla/tree/master/pkstrings).

<!-- toc -->

- [`zip2exe_unpack.py`](#zip2exe_unpackpy)
- [`pksfx_text_tool.py`](#pksfx_text_toolpy)
- [`pksfx_resource_tool.py`](#pksfx_resource_toolpy)
- [External links](#external-links)

<!-- tocstop -->

---

## `zip2exe_unpack.py`

The `zip2exe_unpack` utility extracts the decompression stubs from
the (de-PKLITE'd) Registered or Shareware versions of `ZIP2EXE.EXE`.

## `pksfx_text_tool.py`

The `pksfx_text_tool.py` utility can de-obfuscate the main message and error
message blocks in the full (de-PKLITE'd) `PKSFX` stubs.  You can dump these
blocks out to disk files for easy analysis, or de-obfuscate them *in-place*
(in the `PKSFX` binary itself).  It disables the de-obfuscation engine, so
the output binary can be easily modified further with the de-obfuscated
text in place.  This tool supports working with stubs that have been
reconstructed with `pksfx_resource_tool.py`.

## `pksfx_resource_tool.py`

The `pksfx_resource_tool.py` utility allows analysis, dumping, and patching
of the obfuscated text resources in the full (de-PKLITE'd) `PKSFX` stub.

## External links

[Jason Summers'](https://entropymine.com/deark/) utilities:
 * [`deark`](https://github.com/jsummers/deark) - A utility for file format and metadata analysis, data extraction, decompression, and decoding.
 * [`pkla.py`](https://github.com/jsummers/pkla) - Scripts to analyze PKLITE-compressed files, and other PKWARE files.
 * [`pkstrings.py`](https://github.com/jsummers/pkla/tree/master/pkstrings) - a Python script that decodes the obfuscated strings in some DOS executable files from PKWARE.
