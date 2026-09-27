# PKSFX Tools

<!-- toc -->

- [`zip2exe_unpack.py`](#zip2exe_unpackpy)
- [`pksfx_text_tool.py`](#pksfx_text_toolpy)
  * [Disable `PKSFX` herald](#disable-pksfx-herald)
- [`pksfx_resource_tool.py`](#pksfx_resource_toolpy)
  * [Resource inspection](#resource-inspection)
  * [Resource dump](#resource-dump)
  * [Resource patching](#resource-patching)
- [External links](#external-links)

<!-- tocstop -->

---

## `zip2exe_unpack.py`

The `zip2exe_unpack` utility extracts the decompression stubs from the
(de-PKLITE'd) Registered or Shareware version of `ZIP2EXE.EXE`.

```
usage: zip2exe_unpack.py [-h] [-o OUTPUT_DIR] [--deark [DEARK]] [--force] [--list-candidates] input

positional arguments:
  input                 de-PKLITE'd ZIP2EXE.EXE

options:
  -h, --help            show this help message and exit
  -o, --output-dir OUTPUT_DIR
                        output directory (default: zip2exe-stubs)
  --deark [DEARK]       try invoking deark on extracted stubs (optional path)
  --force               overwrite existing extracted files
  --list-candidates     print every plausible outer-XOR MZ candidate
```

## `pksfx_text_tool.py`

The `pksfx_text_tool.py` utility can de-obfuscate the main message and error
message blocks in the full (de-PKLITE'd) *Registered 2.04g* `PKSFX` stub.  You
can dump these blocks out to disk files for easy analysis, or de-obfuscate
them *in-place* (in the `PKSFX` binary itself) and also disables de-obfuscation
engine, so the output binary can be easily modified further, with the
now de-obfuscated text in place.

> [!NOTE]
> Jason Summers' `pkstrings.py` tool calls the main messages block `strings_1`
> and the error message block `strings_2`.

```
usage: pksfx_text_tool.py [-h] [-d DIR] [-p FILE] input

positional arguments:
  input             de-PKLITE'd PKSFX full stub

options:
  -h, --help        show this help message and exit
  -d, --dump DIR    dump de-obfuscated blocks into DIR
  -p, --patch FILE  write new binary with plaintext blocks and decoder disabled
```

The `pksfx_text_tool.py` supports working with stubs that have been
reconstructed with the `pksfx_resource_tool.py` utility, further described
in the next section.

> [!IMPORTANT]
> The `pksfx_text_tool.py` tool does not yet support de-obfuscating the
> herald (which Jason Summers' `pkstrings.py` refers to as the `intro`).

### Disable `PKSFX` herald

Don't like the `PKSFX` herald?

```
PKSFX (R)   FAST!   Self Extract Utility   Version 2.04g   02-01-93
Copr. 1989-1993 PKWARE Inc. All Rights Reserved. Registered version
PKSFX Reg. U.S. Pat. and Tm. Off.
```

It can be disabled.  In the either of the v2.04g (de-PKLTED'd)
Registered or Shareware stubs:

```
12DF: FF -> 90
12E0: D0 -> 90
```

## `pksfx_resource_tool.py`

The `pksfx_resource_tool.py` utility allows analysis, dumping, and patching
of the obfuscated text resources in the full (de-PKLITE'd) *Registered 2.04g*
`PKSFX` stub.

> [!NOTE]
> Jason Summers' `pkstrings.py` tool calls the `registered` resource `reg_info`,
> the `license` resource `terms`, and the `help` resource `usage`.

### Resource inspection

```
$ pksfx_resource_tool.py -h
usage: pksfx_resource_tool.py [-h] {info,dump,patch} ...

Dump/repack the custom PKSFX 2.04g license/help resources.

positional arguments:
  {info,dump,patch}
    info             show detected resource locations and sizes
    dump             decode resources to text files
    patch            replace all three resources and write a new EXE

options:
  -h, --help         show this help message and exit

$ pksfx_resource_tool.py info pksfx.exe
file: pksfx.exe
size: 18530 bytes
load origin: 0x0080

resource          file-off  storage  encoded  decoded  padding  far-pointer
----------------  --------  -------  -------  -------  -------  -----------
registered        0x003BF0      404      228      227      176  03B7:0000
license           0x003D84      478      478      477        0  03B7:0194
help              0x003F62      638      630      629        8  03B7:0372
```

### Resource dump

```
$ pksfx_resource_tool.py dump -h
usage: pksfx_resource_tool.py dump [-h] input output

positional arguments:
  input
  output

options:
  -h, --help  show this help message and exit

$ pksfx_resource_tool.py dump pksfx.exe dump_dir
registered: 227 bytes -> dump_dir/registered.txt (file offset 0x003BF0)
license: 477 bytes -> dump_dir/license.txt (file offset 0x003D84)
help: 629 bytes -> dump_dir/help.txt (file offset 0x003F62)

$ ls -la dump_dir/
drwxr-xr-x 2 user user 4096 Sep 27 11:56 .
drwxr-xr-x 5 user user 4096 Sep 27 11:56 ..
-rw-r--r-- 1 user user  629 Sep 27 11:56 help.txt
-rw-r--r-- 1 user user  477 Sep 27 11:56 license.txt
-rw-r--r-- 1 user user  227 Sep 27 11:56 registered.txt
```

### Resource patching

```
$ ./pksfx_resource_tool.py patch --help
usage: pksfx_resource_tool.py patch [-h] --registered REGISTERED
       --license LICENSE --help-text HELP -o OUTPUT input

positional arguments:
  input

options:
  -h, --help            show this help message and exit
  --registered REGISTERED
                        registered.txt
  --license LICENSE     license.txt
  --help-text HELP      help.txt
  -o, --output OUTPUT

$ ./pksfx_resource_tool.py patch --registered dump_dir/registered.txt \
                                 --license dump_dir/license.txt \
                                 --help-text dump_dir/help.txt \
                                 pksfx.exe -o new_pksfx.exe
wrote: new_pksfx.exe
sha256: 110400674b0e4f921ff351241b2e7ef1d7350164f11fc0d3d117e0aaab23e2c9
```

## External links

* [Jason Summers'](https://github.com/jsummers/pkla) utilities:
  * [`deark`](https://github.com/jsummers/deark)
  * [`pkla.py`](https://github.com/jsummers/pkla)
  * [`pkstrings.py`](https://github.com/jsummers/pkla/tree/master/pkstrings)
