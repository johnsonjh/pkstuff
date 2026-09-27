# Classic DOS PKZIP

<!-- toc -->

- [PKZIP 2.04](#pkzip-204)
- [PKZIP 2.06 (IBM)](#pkzip-206-ibm)
- [PKZIP 2.50](#pkzip-250)
- [PKZIP utilities](#pkzip-utilities)
  * [Authenticity Verification](#authenticity-verification)
    + [`MAKEAV`](#makeav)
    + [`PUTAV`](#putav)
- [External links](#external-links)

<!-- tocstop -->

---

## PKZIP 2.04

The latest DOS PKZIP 2.04 releases are archived here, both in their
original forms including documentation and utilities where available, as
well as binaries that have been ***properly*** unpacked, decrypted, and
*PSP patched* when necessary.  The unpacked versions are useful for further
reverse engineering and analysis and also load faster on slow machines
(like 8086/8088 systems).

|                            Directory | Description                   | Date        |
|-------------------------------------:|:------------------------------|:------------|
| [`2.04/docs`](2.04/docs)             | PKZIP 2.04 Documentation      | 1993-1994   |
| [`2.04/shareware`](2.04/shareware)   | PKZIP 2.04g Shareware         | 02-01-1993  |
| [`2.04/registered`](2.04/registered) | PKZIP 2.04g Registered        | 02-01-1993  |

The above directories are meant to be *additive* (*or cumulative*):
* The files in the **Documentation** directory apply to
  all PKZIP 2.04/2.06 versions.
* The files in the **Shareware** directory represent the complete PKZIP
  **2.04g** shareware release.
* The files in the **Registered** directory *replace* the **2.04g**
  **Shareware** files.
* The files in the **IBM Licensed** directory (*see below*) *replace* the
  **2.04g** **Registered** files.

> [!TIP]
> To make a complete PKZIP binary distribution, first create a directory
> containing all the **Shareware** files, then copy the **Registered** files
> into this same directory.  Make sure that you *overwrite* any files with
> the same name.  If you desire, you can do the same to "upgrade" to the
> **IBM Licensed** 2.06 release, but you should read the following section
> for more details first.

## PKZIP 2.06 (IBM)

|                            Directory | Description                   | Date        |
|-------------------------------------:|:------------------------------|:------------|
| [`2.06/ibm`](2.06/ibm)               | PKZIP **2.06** (IBM Licensed) | 01-24-1994  |

> [!NOTE]
> The **IBM Licensed** PKZIP 2.06 release is equivalent to the **Registered**
> PKZIP 2.04g, except **it does not contain the encryption features of**
> **2.04g** (so it could be exported and distributed to international IBM
> employees).  We don't know any other differences (at this time), so you
> might want to stick with the 2.04g release (certainly if you might ever
> want to create encrypted ZIP archives).

## PKZIP 2.50

We have the DOS PKZIP 2.50 release available as original binaries, as well as
***properly*** unpacked, decrypted, and *PSP patched* unpacked executables.

|                                     Directory | Description               | Date     |
|----------------------------------------------:|:--------------------------|:---------|
| [`2.50/registered/doc`](2.50/registered/docs) | PKZIP 2.50 Documentation  | 1999     |
| [`2.50/registered`](2.50/registered)          | PKZIP 2.50 Registered     | 03-01-99 |

> [!WARNING]
> This is the newest (and last) PKZIP DOS release, **2.50**, but unfortunately
> is is **NOT** **recommended for most users**.  It has **known bugs** (and
> subtle issues) when used on vintage machines that have caused much user
> frustration.  You *really* should be using the classic **2.04g**
> (or **2.06**) releases unless you have a **very** **specific** reason
> not to.

## PKZIP utilities

The for *first time*, updated versions of my classic PKZIP utilities are
being made available and distributed under the open source MIT license.

### Authenticity Verification

Since the Authenticity Verification (PKAV) feature of the older PKZIP 1.x was
trivially compromised (see
[40Hex, Number 8, Volume 2, Issue 4, File 3: FindAV v1.5 (July 27 1992)](https://newtotse.com/oldtotse/en/zines/chaos/chaos166.html),
a completely new PKAV system was introduced with PKZIP 2.x.   The new scheme
was also quickly compromised with PKAV 2.x keygens appearing in 1993.  PKAV
began to be phased out of PKZIP in version 4.0 (which introduced modern
cryptography), and support was removed in PKZIP 7.0.  PKAV still a fun feature
of the classic DOS PKZIP, but no source code was ever released showing how it
works, *until now*.

#### `MAKEAV`

* The [`MAKEAV`](../makeav.c) "PKZIP 2.04/2.06/2.50 Authenticity
  Verification Generator" utility is an open source keygen tool that
  generates the two serial numbers needed to enable PKAV for any given
  company name.

#### `PUTAV`

* The [`PUTAV`](../putav.c) "PKZIP 2.04/2.06/2.50 Put Authenticity
  Verification" utility is an open source clone of the PKWARE `PUTAV` utility
  distributed with registered PKZIP releases.  It embeds the PKAV code
  directly into (registered) `PKZIP.EXE` 2.04/2.06/2.50 executables, enabling
  the use of the `-!` option.

## External links

For more detailed information about PKZIP see:
* [Common ZIP specification](https://commonzip.org/)
* [PCjs PKZIP History article](https://www.pcjs.org/blog/2025/04/05/)
* [Jason Summers' ZIP articles](https://entropymine.wordpress.com/tag/zip/)
* [Just Solve PKZIP article](http://justsolve.archiveteam.org/wiki/PKZIP)
