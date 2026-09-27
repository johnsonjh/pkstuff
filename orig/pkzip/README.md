# Classic DOS PKZIP

## PKZIP 2.05/2.06

The latest DOS PKZIP 2.04/2.06/2.50 releases are archived here, both in their
original form including documentation and utilities where available, as well
as binaries that have been ***properly*** unpacked, decrypted, and
*PSP patched* when necessary.  The unpacked versions are useful for further
reverse engineering and analysis and also load faster on slow machines
(like 8086/8088 systems).

|                           Directory | Description               | Date        |
|------------------------------------:|:--------------------------|:------------|
| [`2.04/docs`](2.04/docs)            | PKZIP 2.04 Documentation  | 1993-1994   |
| [`2.00/shareware`](2.04/shareware)  | PKZIP 2.04g Shareware     | 02-01-1993  |
| [`2.04/registred`](2.04/registered) | PKZIP 2.04g Registered    | 02-01-1993  |
| [`2/04/ibm`](2.04/ibm)              | PKZIP 2.06 (IBM Licensed) | 01-24-1994  |

The above directories are meant to be *additive* (*or cumulative*):
* The files in the **Documentation** directory apply to PKZIP versions.
* The files in the **Shareware** directory represent the complete PKZIP
  **2.04g** release.
* The files in the **Registered** directory replace the **Shareware** files.
* The files in the **IBM Licensed** directory replace the **Registered** files.

> [!TIP]
> To make a complete PKZIP binary distribution, create a directory containing
> all the **Shareware** files, then copy the **Registered** files into this
> same directory.  Make sure that you overwrite files with the same name.

If you desire, you can do the same to "upgrade" to the **IBM Licensed** 2.06
release, but you should read the following section for complete details first.

### IBM PKZIP 2.06

> [!NOTE]
> The **IBM Licensed** PKZIP 2.06 release is equivalent to the **Registered**
> PKZIP 2.04g, except ***it does not contain the encryption features of 2.04g***
> (so it could be exported and distributed to international IBM employees).

We don't know any other differences at this time, so you probably should just
use the 2.04g release (certainyl if you might ever need to create encrypted ZIP
archives).

## PKZIP 2.50

> [!WARNING]
> The later (and final) DOS PKZIP **2.50** release is ***NOT***
> ***recommended***.  It has known bugs and subtle issues when used on vintage
> machines.  You *really* should be using the classic **2.04g** (or **2.06**)
> version unless you have a **very** **specific** reason not to.

|                                    Directory | Description               | Date     |
|---------------------------------------------:|:--------------------------|:---------|
| [`2.50/registred/doc`](2.50/registered/docs) | PKZIP 2.50 Documentation  | 1999     |
| [`2.50/registred`](2.50/registered)          | PKZIP 2.50 Registered     | 03-01-99 |

## External links

* For more detailed information about PKZIP see:
  * [Common ZIP specificatin](https://commonzip.org/)
  * [PCjs PKZIP History article](https://www.pcjs.org/blog/2025/04/05/)
  * [Just Solve PKZIP article](http://justsolve.archiveteam.org/wiki/PKZIP)
