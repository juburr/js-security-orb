// licenses.mjs: the licenses command of js-security-orb's Node.js helper
// (Node >= 22, standard library only). It checks the license of every package
// the lockfiles lock against allowed_licenses, with a strict SPDX expression
// parser and the SPDX License List's identifiers embedded below.
//
// Where a license comes from, for each registry entry (name@version):
//   1. clarify, when a line matches it (name@version over name, a name over a
//      glob such as @corp/*; the first line among equals). Its package isn't
//      fetched at all.
//   2. Otherwise the full packument's version document, from the registry
//      core's metadataRegistry gives, the rule every command follows (registry
//      or a scope registry; a package recorded on registry.npmjs.org is read
//      from the registry configured for its name, as npm installs it):
//      `license` (an SPDX expression, the legacy object {type}, or an array,
//      which is OR-ed), falling back, only when `license` is absent or empty,
//      to the legacy `licenses` array, whose items are OR-ed, as pnpm does.
//      getPackuments' pick keeps only those two fields of the locked versions.
//   3. With offline: true, the lockfile's own `license`, which only npm
//      lockfiles of version 2 and 3 record. Any other lockfile is an error (no
//      verdict). npm drops the legacy `licenses` array, so those packages read
//      as having no license; core reads an array in `license` as its items
//      OR-ed, as step 2 does.
//
// Decisions:
//   - Expressions follow SPDX 2.3 Annex D: WITH binds tighter than AND, AND
//     than OR; parentheses group. Operators are matched ignoring case (as npm's
//     spdx-expression-parse does), license and exception identifiers ignoring
//     case and rewritten in the list's case. LicenseRef-, DocumentRef-…:
//     LicenseRef- and, after WITH, AdditionRef- are matched exactly. "+" must
//     follow an identifier with no space between. Anything else is an error,
//     with the 1-based column where the expression stops making sense.
//   - Deprecated identifiers are valid. The GNU family's bare forms, which SPDX
//     replaced by -only and -or-later, are rewritten so they can be checked:
//     GPL-2.0 is GPL-2.0-only, GPL-2.0+ is GPL-2.0-or-later (likewise X-only+);
//     the report lists the deprecated identifiers a package used. The other
//     deprecated identifiers stay as they are.
//   - UNLICENSED, SEE LICENSE IN <file>, NONE, NOASSERTION, free text and
//     anything else that doesn't parse are "unknown" findings, never a pass,
//     until clarify says what the license is. So are a missing license, a
//     package the registry doesn't have, and a field of the wrong type.
//   - Policy: OR needs one allowed side, AND every part. X WITH E needs X
//     allowed, and E listed too once allowed_licenses lists any exception (an
//     exception only adds permissions); an AdditionRef- must always be listed.
//     X+ and X-or-later are allowed by X-or-later, or by X (X-only): "or
//     later" lets you take version X. LicenseRef- entries are allowed only when
//     listed exactly.
//   - allowed_licenses takes identifiers only, checked against the list; the
//     GNU bare forms are refused there, and in clarify, since packages' are
//     read as -only. clarify takes core's package patterns (globs allowed), and
//     every expression is parsed before anything is read; a line that matches
//     no checked package is a warning.
//   - Only registry entries are checked. git, remote (tarball URL), local
//     (file:), link and workspace entries are listed as skipped (with a
//     warning for git and remote ones), and so are registry entries recorded
//     from a registry that is neither registry nor a scope registry, which is
//     never contacted. With offline, the lockfile records the license whatever
//     the registry, so those are checked. The project's own workspace
//     packages aren't checked: their license is the project's choice.
//   - A registry that can't be read (a transfer error, 401, 403, 5xx) is no
//     verdict, except a 401 or 403 from a scope registry on another origin
//     than registry, which never gets the token: its packages are skipped
//     with a warning (core's unauthorizedSkip, as in every command). A 404 or
//     a missing version is an unknown license.
//   - Packages are counted once per name@version; findings are made once per
//     lockfile the package is in, at its first line there.
//
// The SPDX identifiers: generated from spdx/license-list-data at tag v3.29.0
// (json/licenses.json, SHA-256 47d1cc681abe31166b342b6cc4aab13a6ba8ea5c48794697fe3bf8b1dbaf509a;
// json/exceptions.json, SHA-256 59ee7c150de521d635cbf9367b8cf543b8da6781ea3ac1c073d305524f84ada2),
// sorted by code point, wrapped at 110 columns, identifiers only. The six
// deprecated "X+" identifiers (GPL-2.0+ and the like) are left out, since the
// parser reads them as X with "+". To refresh, regenerate the four lists the
// same way from a newer tag, update SPDX_LIST_VERSION, and the counts the
// tests check.

import {
  main, isMain, metadataRegistry, unauthorizedSkip, authHint, skipWarning, UsageError, show, plural, splitList, compilePattern, publicUrl,
} from './core.mjs';

/** The allowlist used when allowed_licenses is not set. */
export const DEFAULT_ALLOWED_LICENSES = '0BSD,Apache-2.0,BlueOak-1.0.0,BSD-2-Clause,BSD-3-Clause,CC0-1.0,ISC,MIT,Unlicense';

// ---------------------------------------------------------------------------
// The SPDX License List
// ---------------------------------------------------------------------------

// SPDX License List 3.29.0 (2026-09-16): 708 licenses, 32 deprecated (6 of them X+, left out), 86 exceptions (1 deprecated)
const SPDX_LIST_VERSION = '3.29.0';
const SPDX_LICENSES = `
0BSD 3D-Slicer-1.0 AAL ADSL AFL-1.1 AFL-1.2 AFL-2.0 AFL-2.1 AFL-3.0 AGPL-1.0-only AGPL-1.0-or-later
AGPL-3.0-only AGPL-3.0-or-later ALGLIB-Documentation AMD-newlib AMDPLPA AML AML-glslang AMPAS ANTLR-PD
ANTLR-PD-fallback APAFML APL-1.0 APSL-1.0 APSL-1.1 APSL-1.2 APSL-2.0 ASWF-Digital-Assets-1.0
ASWF-Digital-Assets-1.1 Abstyles AdaCore-doc Adobe-2006 Adobe-Display-PostScript Adobe-Glyph Adobe-Utopia
Advanced-Cryptics-Dictionary Afmparse Aladdin Apache-1.0 Apache-1.1 Apache-2.0 App-s2p Arphic-1999
Artistic-1.0 Artistic-1.0-Perl Artistic-1.0-cl8 Artistic-2.0 Artistic-dist Aspell-RU BOLA-1.1 BSD-1-Clause
BSD-2-Clause BSD-2-Clause-Darwin BSD-2-Clause-Patent BSD-2-Clause-Views BSD-2-Clause-first-lines
BSD-2-Clause-pkgconf-disclaimer BSD-2-Clause-pos-unchanged BSD-3-Clause BSD-3-Clause-Attribution
BSD-3-Clause-Clear BSD-3-Clause-HP BSD-3-Clause-LBNL BSD-3-Clause-Modification
BSD-3-Clause-No-Military-License BSD-3-Clause-No-Nuclear-License BSD-3-Clause-No-Nuclear-License-2014
BSD-3-Clause-No-Nuclear-Warranty BSD-3-Clause-Open-MPI BSD-3-Clause-OpenWebUI BSD-3-Clause-Sun
BSD-3-Clause-Tso BSD-3-Clause-acpica BSD-3-Clause-flex BSD-4-Clause BSD-4-Clause-Shortened BSD-4-Clause-UC
BSD-4.3RENO BSD-4.3TAHOE BSD-Advertising-Acknowledgement BSD-Attribution-HPND-disclaimer BSD-Inferno-Nettverk
BSD-Mark-Modifications BSD-Protection BSD-Source-Code BSD-Source-Code-no-disclaimer BSD-Source-alt-GPL
BSD-Source-beginning-file BSD-Systemics BSD-Systemics-W3Works BSD-ask-to-endorse BSL-1.0 BUSL-1.1 Baekmuk
Bahyph Barr Beerware BitTorrent-1.0 BitTorrent-1.1 Bitstream-Charter Bitstream-Vera BlueOak-1.0.0 Boehm-GC
Boehm-GC-without-fee Borceux Brian-Gladman-2-Clause Brian-Gladman-3-Clause
Brian-Gladman-3-Clause-no-conversion Buddy Bugroff C-UDA-1.0 CAL-1.0 CAL-1.0-Combined-Work-Exception CAPEC-tou
CATOSL-1.1 CC-BY-1.0 CC-BY-2.0 CC-BY-2.5 CC-BY-2.5-AU CC-BY-3.0 CC-BY-3.0-AT CC-BY-3.0-AU CC-BY-3.0-DE
CC-BY-3.0-IGO CC-BY-3.0-NL CC-BY-3.0-US CC-BY-4.0 CC-BY-NC-1.0 CC-BY-NC-2.0 CC-BY-NC-2.5 CC-BY-NC-3.0
CC-BY-NC-3.0-DE CC-BY-NC-3.0-IGO CC-BY-NC-4.0 CC-BY-NC-ND-1.0 CC-BY-NC-ND-2.0 CC-BY-NC-ND-2.5 CC-BY-NC-ND-3.0
CC-BY-NC-ND-3.0-DE CC-BY-NC-ND-3.0-IGO CC-BY-NC-ND-4.0 CC-BY-NC-SA-1.0 CC-BY-NC-SA-2.0 CC-BY-NC-SA-2.0-DE
CC-BY-NC-SA-2.0-FR CC-BY-NC-SA-2.0-UK CC-BY-NC-SA-2.5 CC-BY-NC-SA-3.0 CC-BY-NC-SA-3.0-DE CC-BY-NC-SA-3.0-IGO
CC-BY-NC-SA-4.0 CC-BY-ND-1.0 CC-BY-ND-2.0 CC-BY-ND-2.5 CC-BY-ND-3.0 CC-BY-ND-3.0-DE CC-BY-ND-4.0 CC-BY-SA-1.0
CC-BY-SA-2.0 CC-BY-SA-2.0-UK CC-BY-SA-2.1-JP CC-BY-SA-2.5 CC-BY-SA-3.0 CC-BY-SA-3.0-AT CC-BY-SA-3.0-DE
CC-BY-SA-3.0-IGO CC-BY-SA-4.0 CC-PDDC CC-PDM-1.0 CC-SA-1.0 CC0-1.0 CDDL-1.0 CDDL-1.1 CDL-1.0
CDLA-Permissive-1.0 CDLA-Permissive-2.0 CDLA-Sharing-1.0 CECILL-1.0 CECILL-1.1 CECILL-2.0 CECILL-2.1 CECILL-B
CECILL-C CERN-OHL-1.1 CERN-OHL-1.2 CERN-OHL-P-2.0 CERN-OHL-S-2.0 CERN-OHL-W-2.0 CFITSIO CMU-Mach
CMU-Mach-nodoc CNRI-Jython CNRI-Python CNRI-Python-GPL-Compatible COIL-1.0 CPAL-1.0 CPL-1.0 CPOL-1.02
CUA-OPL-1.0 Caldera Caldera-no-preamble Catharon ClArtistic Clips Community-Spec-1.0 Condor-1.1
Cornell-Lossless-JPEG Cronyx Crossword CryptoSwift CrystalStacker Cube D-FSL-1.0 DEC-3-Clause DL-DE-BY-2.0
DL-DE-ZERO-2.0 DOC DRL-1.0 DRL-1.1 DSDP DocBook-DTD DocBook-Schema DocBook-Stylesheet DocBook-XML Dotseqn
ECL-1.0 ECL-2.0 EFL-1.0 EFL-2.0 EPICS EPL-1.0 EPL-2.0 ESA-PL-permissive-2.4 ESA-PL-strong-copyleft-2.4
ESA-PL-weak-copyleft-2.4 EUDatagrid EUPL-1.0 EUPL-1.1 EUPL-1.2 Elastic-2.0 Entessa ErlPL-1.1 Eurosym FBM
FDK-AAC FDK-MPEG-H FSFAP FSFAP-no-warranty-disclaimer FSFUL FSFULLR FSFULLRSD FSFULLRWD FSL-1.1-ALv2
FSL-1.1-MIT FTL Fair Ferguson-Twofish Frameworx-1.0 FreeBSD-DOC FreeImage Furuseth GCR-docs GD
GFDL-1.1-invariants-only GFDL-1.1-invariants-or-later GFDL-1.1-no-invariants-only
GFDL-1.1-no-invariants-or-later GFDL-1.1-only GFDL-1.1-or-later GFDL-1.2-invariants-only
GFDL-1.2-invariants-or-later GFDL-1.2-no-invariants-only GFDL-1.2-no-invariants-or-later GFDL-1.2-only
GFDL-1.2-or-later GFDL-1.3-invariants-only GFDL-1.3-invariants-or-later GFDL-1.3-no-invariants-only
GFDL-1.3-no-invariants-or-later GFDL-1.3-only GFDL-1.3-or-later GL2PS GLWTPL GPL-1.0-only GPL-1.0-or-later
GPL-2.0-only GPL-2.0-or-later GPL-3.0-only GPL-3.0-or-later Game-Programming-Gems Giftware Glide Glulxe
Graphics-Gems Gutmann HDF5 HIDAPI HP-1986 HP-1989 HPND HPND-DEC HPND-Fenneberg-Livingston HPND-INRIA-IMAG
HPND-Intel HPND-Kevlin-Henney HPND-MIT-disclaimer HPND-Markus-Kuhn HPND-Netrek HPND-Pbmplus HPND-SMC HPND-UC
HPND-UC-export-US HPND-doc HPND-doc-sell HPND-export-US HPND-export-US-acknowledgement HPND-export-US-modify
HPND-export2-US HPND-merchantability-variant HPND-sell-MIT-disclaimer-xserver HPND-sell-regexpr
HPND-sell-variant HPND-sell-variant-MIT-disclaimer HPND-sell-variant-MIT-disclaimer-rev
HPND-sell-variant-critical-systems HTMLTIDY HaskellReport Hippocratic-2.1 Hippocratic-3.0-core IBM-pibs ICU
IEC-Code-Components-EULA IJG IJG-short IPA IPL-1.0 ISC ISC-Veillard ISO-permission ImageMagick Imlib2 Info-ZIP
Informatica Inner-Net-2.0 InnoSetup Intel Intel-ACPI Interbase-1.0 JPL-image JPNIC JSON Jam JasPer-2.0 Kastrup
Kazlib Knuth-CTAN LAL-1.2 LAL-1.3 LGPL-2.0-only LGPL-2.0-or-later LGPL-2.1-only LGPL-2.1-or-later
LGPL-3.0-only LGPL-3.0-or-later LGPLLR LOOP LPD-document LPL-1.0 LPL-1.02 LPPL-1.0 LPPL-1.1 LPPL-1.2 LPPL-1.3a
LPPL-1.3c LZMA-SDK-9.11-to-9.20 LZMA-SDK-9.22 Latex2e Latex2e-translated-notice Leptonica LiLiQ-P-1.1
LiLiQ-R-1.1 LiLiQ-Rplus-1.1 Libpng Linux-OpenIB Linux-man-pages-1-para Linux-man-pages-copyleft
Linux-man-pages-copyleft-2-para Linux-man-pages-copyleft-var Lucida-Bitmap-Fonts MIPS MIT MIT-0 MIT-CMU
MIT-Click MIT-Festival MIT-Khronos-old MIT-Modern-Variant MIT-STK MIT-Wu MIT-advertising MIT-enna MIT-feh
MIT-open-group MIT-testregex MITNFA MMIXware MMPL-1.0.1 MPEG-SSG MPL-1.0 MPL-1.1 MPL-2.0
MPL-2.0-no-copyleft-exception MS-LPL MS-PL MS-RL MTLL MVT-1.1 Mackerras-3-Clause
Mackerras-3-Clause-acknowledgment MakeIndex Martin-Birgmeier McPhee-slideshow Minpack MirOS Motosoto
MulanPSL-1.0 MulanPSL-2.0 Multics Mup NAIST-2003 NASA-1.3 NBPL-1.0 NCBI-PD NCGL-UK-2.0 NCL NCSA NGPL NICTA-1.0
NIST-PD NIST-PD-TNT NIST-PD-fallback NIST-Software NLOD-1.0 NLOD-2.0 NLPL NOSL NPL-1.0 NPL-1.1 NPOSL-3.0 NRL
NTIA-PD NTP NTP-0 Naumen NetCDF Newsletr Nokia Noweb O-UDA-1.0 OAR OCCT-PL OCLC-2.0 ODC-By-1.0 ODbL-1.0 OFFIS
OFL-1.0 OFL-1.0-RFN OFL-1.0-no-RFN OFL-1.1 OFL-1.1-RFN OFL-1.1-no-RFN OGC-1.0 OGDL-Taiwan-1.0 OGL-Canada-2.0
OGL-UK-1.0 OGL-UK-2.0 OGL-UK-3.0 OGTSL OLDAP-1.1 OLDAP-1.2 OLDAP-1.3 OLDAP-1.4 OLDAP-2.0 OLDAP-2.0.1 OLDAP-2.1
OLDAP-2.2 OLDAP-2.2.1 OLDAP-2.2.2 OLDAP-2.3 OLDAP-2.4 OLDAP-2.5 OLDAP-2.6 OLDAP-2.7 OLDAP-2.8 OLFL-1.3 OML
OPL-1.0 OPL-UK-3.0 OPUBL-1.0 OSC-1.0 OSET-PL-2.1 OSL-1.0 OSL-1.1 OSL-2.0 OSL-2.1 OSL-3.0 OSSP OpenMDW-1.0
OpenPBS-2.3 OpenSSL OpenSSL-standalone OpenVision PADL PDDL-1.0 PHP-3.0 PHP-3.01 PPL PSF-2.0
ParaType-Free-Font-1.3 Parity-6.0.0 Parity-7.0.0 Pixar Plexus PolyForm-Noncommercial-1.0.0
PolyForm-Small-Business-1.0.0 PostgreSQL Python-2.0 Python-2.0.1 QPL-1.0 QPL-1.0-INRIA-2004 Qhull RHeCos-1.1
RPL-1.1 RPL-1.5 RPSL-1.0 RSA-MD RSCPL Rdisc Ruby Ruby-pty SAX-PD SAX-PD-2.0 SCEA SGI-B-1.0 SGI-B-1.1 SGI-B-2.0
SGI-OpenGL SGMLUG-PM SGP4 SHL-0.5 SHL-0.51 SISSL SISSL-1.2 SL SMAIL-GPL SMLNJ SMPPL SNIA SOFA SPL-1.0
SSH-OpenSSH SSH-short SSLeay-standalone SSPL-1.0 SUL-1.0 SWL Saxpath SchemeReport Sendmail Sendmail-8.23
Sendmail-Open-Source-1.1 SimPL-2.0 Sleepycat Soundex Spencer-86 Spencer-94 Spencer-99 SugarCRM-1.1.3 Sun-PPP
Sun-PPP-2000 SunPro Symlinks TAPR-OHL-1.0 TCL TCP-wrappers TGPPL-1.0 TMate TORQUE-1.1 TOSL TPDL TPL-1.0 TTWL
TTYP0 TU-Berlin-1.0 TU-Berlin-2.0 TekHVC TermReadKey ThirdEye TrustedQSL UCAR UCL-1.0 UMich-Merit UPL-1.0
URT-RLE Ubuntu-font-1.0 UnRAR Unicode-3.0 Unicode-DFS-2015 Unicode-DFS-2016 Unicode-TOU UnixCrypt Unlicense
Unlicense-libtelnet Unlicense-libwhirlpool VOSTROM VSL-1.0 Vim Vixie-Cron W3C W3C-19980720 W3C-20150513
WTFNMFPL WTFPL Watcom-1.0 Widget-Workshop WordNet Wsuipa X11 X11-distribute-modifications-variant
X11-no-permit-persons X11-swapped XFree86-1.1 XSkat Xdebug-1.03 Xerox Xfig Xnet YPL-1.0 YPL-1.1 ZPL-1.1
ZPL-2.0 ZPL-2.1 Zed Zeeff Zend-2.0 Zimbra-1.3 Zimbra-1.4 Zlib any-OSI any-OSI-perl-modules atc-game
bcrypt-Solar-Designer blessing bzip2-1.0.6 check-cvs checkmk copyleft-next-0.3.0 copyleft-next-0.3.1 curl
cve-tou diffmark dtoa dvipdfm eGenix etalab-2.0 fwlw gSOAP-1.3b generic-xts gnuplot gtkbook hdparm
hyphen-bulgarian iMatix jove libpng-1.6.35 libpng-2.0 libselinux-1.0 libtiff libutil-David-Nugent lsof magaz
mailprio man2html metamail mpi-permissive mpich2 mplus ngrep pkgconf pnmstitch psfrag psutils python-ldap
radvd snprintf softSurfer ssh-keyscan swrule threeparttable ulem w3m wwl xinetd xkeyboard-config-Zinoviev
xlock xpp xzoom zlib-acknowledgement`;
const SPDX_DEPRECATED_LICENSES = `
AGPL-1.0 AGPL-3.0 BSD-2-Clause-FreeBSD BSD-2-Clause-NetBSD GFDL-1.1 GFDL-1.2 GFDL-1.3 GPL-1.0 GPL-2.0
GPL-2.0-with-GCC-exception GPL-2.0-with-autoconf-exception GPL-2.0-with-bison-exception
GPL-2.0-with-classpath-exception GPL-2.0-with-font-exception GPL-3.0 GPL-3.0-with-GCC-exception
GPL-3.0-with-autoconf-exception LGPL-2.0 LGPL-2.1 LGPL-3.0 Net-SNMP Nunit StandardML-NJ bzip2-1.0.5 eCos-2.0
wxWindows`;
const SPDX_EXCEPTIONS = `
389-exception Asterisk-exception Asterisk-linking-protocols-exception Autoconf-exception-2.0
Autoconf-exception-3.0 Autoconf-exception-generic Autoconf-exception-generic-3.0 Autoconf-exception-macro
Bison-exception-1.24 Bison-exception-2.2 Bootloader-exception CGAL-linking-exception CLISP-exception-2.0
Classpath-exception-2.0 Classpath-exception-2.0-short DigiRule-FOSS-exception Digia-Qt-LGPL-exception-1.1
FLTK-exception Fawkes-Runtime-exception Font-exception-2.0 GCC-exception-2.0 GCC-exception-2.0-note
GCC-exception-3.1 GNAT-exception GNOME-examples-exception GNU-compiler-exception GPL-3.0-389-ds-base-exception
GPL-3.0-interface-exception GPL-3.0-linking-exception GPL-3.0-linking-source-exception GPL-CC-1.0
GStreamer-exception-2005 GStreamer-exception-2008 Gmsh-exception Google-Patent-WebM
Independent-modules-exception KiCad-libraries-exception LGPL-3.0-linking-exception LLGPL LLVM-exception
LZMA-exception Libtool-exception Linux-syscall-note OCCT-exception-1.0 OCaml-LGPL-linking-exception
OpenJDK-assembly-exception-1.0 PCRE2-exception PS-or-PDF-font-exception-20170817 QPL-1.0-INRIA-2004-exception
Qt-GPL-exception-1.0 Qt-LGPL-exception-1.1 Qwt-exception-1.0 RRDtool-FLOSS-exception-2.0 SANE-exception
SHL-2.0 SHL-2.1 SWI-exception Simple-Library-Usage-exception Spelling-Provider-LGPL-exception Swift-exception
Texinfo-exception UBDL-exception Universal-FOSS-exception-1.0 WxWindows-exception-3.1
cryptsetup-OpenSSL-exception eCos-exception-2.0 erlang-otp-linking-exception fmt-exception
freertos-exception-2.0 gnu-javamail-exception harbour-exception i2p-gpl-java-exception kvirc-openssl-exception
libpri-OpenH323-exception mif-exception mxml-exception openvpn-openssl-exception polyparse-exception
romic-exception rsync-linking-exception sqlitestudio-OpenSSL-exception stunnel-exception u-boot-exception-2.0
vsftpd-openssl-exception x11vnc-openssl-exception`;
const SPDX_DEPRECATED_EXCEPTIONS = `
Nokia-Qt-exception-1.1`;

export { SPDX_LIST_VERSION };

const words = (s) => s.split(/\s+/).filter(Boolean);
const LICENSES = new Map();
const EXCEPTIONS = new Map();
for (const [list, map, deprecated] of [[SPDX_LICENSES, LICENSES, false], [SPDX_DEPRECATED_LICENSES, LICENSES, true],
  [SPDX_EXCEPTIONS, EXCEPTIONS, false], [SPDX_DEPRECATED_EXCEPTIONS, EXCEPTIONS, true]]) {
  for (const id of words(list)) map.set(id.toLowerCase(), { id, deprecated });
}
// Deprecated GNU identifiers whose meaning SPDX split into X-only and X-or-later.
const GNU_BARE = new Set([...LICENSES.values()].filter((l) => l.deprecated && LICENSES.has(`${l.id}-only`.toLowerCase())
  && LICENSES.has(`${l.id}-or-later`.toLowerCase())).map((l) => l.id));

/**
 * Looks up a license identifier, ignoring case.
 * @param {string} id
 * @returns {{id: string, deprecated: boolean}|null} the identifier as the list writes it
 */
export function lookupLicense(id) {
  return LICENSES.get(String(id).toLowerCase()) ?? null;
}

/**
 * Looks up a license exception identifier, ignoring case.
 * @param {string} id
 * @returns {{id: string, deprecated: boolean}|null}
 */
export function lookupException(id) {
  return EXCEPTIONS.get(String(id).toLowerCase()) ?? null;
}

/** How many identifiers the embedded list holds, for the tests. */
export function spdxCounts() {
  const count = (map, deprecated) => [...map.values()].filter((v) => v.deprecated === deprecated).length;
  return { licenses: count(LICENSES, false), deprecatedLicenses: count(LICENSES, true), exceptions: count(EXCEPTIONS, false), deprecatedExceptions: count(EXCEPTIONS, true) };
}

// ---------------------------------------------------------------------------
// The SPDX expression parser
// ---------------------------------------------------------------------------

/** An expression that doesn't parse: column is 1-based, in the expression as given. */
export class SpdxError extends Error {
  constructor(message, column) {
    super(message);
    this.name = 'SpdxError';
    this.column = column;
  }
}

const MAX_LENGTH = 1000;
const MAX_DEPTH = 32;
const ID = '[A-Za-z0-9.-]+';
const LICENSE_REF_RE = new RegExp(`^(?:DocumentRef-${ID}:)?LicenseRef-${ID}$`);
const ADDITION_REF_RE = new RegExp(`^(?:DocumentRef-${ID}:)?AdditionRef-${ID}$`);
const WORD_RE = /[A-Za-z0-9.-]+(?::[A-Za-z0-9.-]+)?/y;
const OPERATORS = new Set(['AND', 'OR', 'WITH']);

function badChar(c) {
  return c === '\n' || c === '\r' ? 'a line break, which an expression can\'t hold' : `unexpected character ${JSON.stringify(c)}`;
}

function tokenize(text) {
  const tokens = [];
  let i = 0;
  while (i < text.length) {
    const c = text[i];
    if (c === ' ' || c === '\t') { i++; continue; }
    if (c === '(' || c === ')') { tokens.push({ t: c, col: i + 1 }); i++; continue; }
    if (c === '+') {
      const prev = tokens.at(-1);
      if (!prev || prev.t !== 'word' || prev.end !== i) throw new SpdxError('"+" must follow a license identifier, with no space before it', i + 1);
      if (prev.plus) throw new SpdxError('a second "+"', i + 1);
      prev.plus = i + 1;
      prev.end = i + 1;
      i++;
      continue;
    }
    WORD_RE.lastIndex = i;
    const m = WORD_RE.exec(text);
    if (!m) throw new SpdxError(badChar(c), i + 1);
    tokens.push({ t: 'word', text: m[0], col: i + 1, end: i + m[0].length, plus: 0 });
    i += m[0].length;
  }
  return tokens;
}

const tokenText = (tok) => show(tok.t === 'word' ? tok.text : tok.t);
const opOf = (tok) => (tok && tok.t === 'word' && OPERATORS.has(tok.text.toUpperCase()) ? tok.text.toUpperCase() : null);

function joinNodes(type, args) {
  const flat = [];
  for (const a of args) if (a.type === type) flat.push(...a.args); else flat.push(a);
  return flat.length === 1 ? flat[0] : { type, args: flat };
}

/**
 * Renders a parsed expression: identifiers in the list's case, operators in
 * upper case, parentheses only where OR sits inside AND.
 * @param {object} node
 * @returns {string}
 */
export function renderNode(node) {
  switch (node.type) {
    case 'license': return node.id + (node.plus ? '+' : '');
    case 'ref': return node.id;
    case 'with': return `${renderNode(node.license)} WITH ${node.exception.id}`;
    case 'and': return node.args.map((a) => (a.type === 'or' ? `(${renderNode(a)})` : renderNode(a))).join(' AND ');
    case 'or': return node.args.map(renderNode).join(' OR ');
    default: throw new Error(`Internal error: a node of type ${show(node.type)}.`);
  }
}

// A license identifier, with the GNU family's deprecated forms rewritten.
function licenseNode(id, plus, notes) {
  const lic = LICENSES.get(id.toLowerCase());
  if (lic.deprecated) notes.deprecated.add(lic.id + (plus ? '+' : ''));
  if (GNU_BARE.has(lic.id)) {
    const to = `${lic.id}-${plus ? 'or-later' : 'only'}`;
    notes.rewritten.push({ from: lic.id + (plus ? '+' : ''), to });
    return { type: 'license', id: to, plus: false };
  }
  if (plus && lic.id.endsWith('-only') && LICENSES.has(`${lic.id.slice(0, -5)}-or-later`.toLowerCase())) {
    const to = `${lic.id.slice(0, -5)}-or-later`;
    notes.rewritten.push({ from: `${lic.id}+`, to });
    return { type: 'license', id: to, plus: false };
  }
  if (plus && lic.id.endsWith('-or-later')) return { type: 'license', id: lic.id, plus: false };
  return { type: 'license', id: lic.id, plus: !!plus };
}

/**
 * Parses an SPDX license expression strictly.
 * @param {string} text
 * @returns {{node: object, expression: string, deprecated: string[], rewritten: {from, to}[]}}
 *   expression is the rendered, normalized form
 * @throws {SpdxError} with the 1-based column where it stops making sense
 */
export function parseSpdx(text) {
  if (typeof text !== 'string') throw new SpdxError('not a string', 1);
  if (text.length > MAX_LENGTH) throw new SpdxError(`longer than ${MAX_LENGTH} characters`, MAX_LENGTH + 1);
  const tokens = tokenize(text);
  const endCol = text.replace(/[ \t]+$/, '').length + 1;
  const notes = { deprecated: new Set(), rewritten: [] };
  let k = 0;
  const peek = () => tokens[k];

  const simple = (tok) => {
    const t = tok.text;
    if (LICENSE_REF_RE.test(t)) {
      if (tok.plus) throw new SpdxError('"+" can\'t follow a LicenseRef', tok.plus);
      return { type: 'ref', id: t };
    }
    if (ADDITION_REF_RE.test(t)) throw new SpdxError(`${t} is an AdditionRef, which must follow WITH`, tok.col);
    if (t.includes(':')) throw new SpdxError('a ":" belongs only in DocumentRef-…:LicenseRef-…', tok.col + t.indexOf(':'));
    if (LICENSES.has(t.toLowerCase())) return licenseNode(t, tok.plus, notes);
    const exc = EXCEPTIONS.get(t.toLowerCase());
    if (exc) throw new SpdxError(`${exc.id} is a license exception, which must follow WITH`, tok.col);
    if (/^UNLICEN[CS]ED$/i.test(t)) throw new SpdxError('UNLICENSED can\'t be part of an expression', tok.col);
    if (/^(?:NONE|NOASSERTION)$/i.test(t)) throw new SpdxError(`${t.toUpperCase()} says there is no license information, and is not a license`, tok.col);
    if (/^licenseref-/i.test(t)) {
      throw new SpdxError(t.startsWith('LicenseRef-') ? `${show(t)} needs an idstring after LicenseRef-` : `${show(t)} must start with LicenseRef-, in that case`, tok.col);
    }
    throw new SpdxError(`${show(t)} is not an SPDX license identifier`, tok.col);
  };

  const exception = () => {
    const tok = peek();
    if (!tok) throw new SpdxError('a license exception is missing after WITH', endCol);
    if (tok.t !== 'word' || opOf(tok)) throw new SpdxError(`expected a license exception after WITH, not ${tokenText(tok)}`, tok.col);
    k++;
    if (tok.plus) throw new SpdxError('"+" can\'t follow a license exception', tok.plus);
    if (ADDITION_REF_RE.test(tok.text)) return { id: tok.text, ref: true };
    const exc = EXCEPTIONS.get(tok.text.toLowerCase());
    if (exc) {
      if (exc.deprecated) notes.deprecated.add(exc.id);
      return { id: exc.id, ref: false };
    }
    const lic = LICENSES.get(tok.text.toLowerCase());
    if (lic) throw new SpdxError(`${lic.id} is a license, not a license exception`, tok.col);
    throw new SpdxError(`${show(tok.text)} is not an SPDX license exception identifier`, tok.col);
  };

  let expression;
  const primary = (depth, after) => {
    const tok = peek();
    if (!tok) throw new SpdxError(after ? `a license is missing after ${after}` : 'the expression is empty', endCol);
    if (tok.t === '(') {
      if (depth >= MAX_DEPTH) throw new SpdxError('parentheses nested too deeply', tok.col);
      k++;
      const inner = expression(depth + 1, '"("');
      const close = peek();
      if (!close) throw new SpdxError(`a ")" is missing for the "(" at column ${tok.col}`, endCol);
      if (close.t !== ')') throw new SpdxError(`expected AND, OR, WITH or ")" here, not ${tokenText(close)}`, close.col);
      k++;
      return inner;
    }
    if (tok.t === ')') throw new SpdxError(after ? `a license is missing after ${after}` : 'unexpected ")"', tok.col);
    const op = opOf(tok);
    if (op) throw new SpdxError(`expected a license, not ${op}`, tok.col);
    k++;
    const node = simple(tok);
    if (opOf(peek()) === 'WITH') {
      k++;
      return { type: 'with', license: node, exception: exception() };
    }
    return node;
  };
  const conjunction = (depth, after) => {
    const args = [primary(depth, after)];
    while (opOf(peek()) === 'AND') {
      const tok = tokens[k++];
      if (tok.plus) throw new SpdxError('"+" can\'t follow AND', tok.plus);
      args.push(primary(depth, 'AND'));
    }
    return joinNodes('and', args);
  };
  expression = (depth, after) => {
    const args = [conjunction(depth, after)];
    while (opOf(peek()) === 'OR') {
      const tok = tokens[k++];
      if (tok.plus) throw new SpdxError('"+" can\'t follow OR', tok.plus);
      args.push(conjunction(depth, 'OR'));
    }
    return joinNodes('or', args);
  };

  const node = expression(0);
  if (k < tokens.length) {
    const tok = tokens[k];
    if (tok.t === ')') throw new SpdxError('unexpected ")"', tok.col);
    if (tok.t === '(') throw new SpdxError('expected AND, OR or WITH before "("', tok.col);
    if (opOf(tok) === 'WITH') throw new SpdxError('WITH must follow a license identifier, not a parenthesized expression', tok.col);
    throw new SpdxError(`expected AND, OR or WITH here, not ${tokenText(tok)}`, tok.col);
  }
  return { node, expression: renderNode(node), deprecated: [...notes.deprecated], rewritten: notes.rewritten };
}

// ---------------------------------------------------------------------------
// License fields
// ---------------------------------------------------------------------------

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const absent = (v) => v === undefined || v === null || (typeof v === 'string' && !v.trim()) || (Array.isArray(v) && !v.length);

/**
 * Reads one license string: an SPDX expression, or one of the forms that
 * name no license the check can read.
 * @param {string} text
 * @returns {{status: 'ok', node, expression, deprecated, rewritten} |
 *   {status: 'unknown', reason: 'missing'|'unlicensed'|'see-license-in'|'invalid', file?, text?, error?, column?}}
 *   file for see-license-in; text, error and column (1-based) for invalid
 */
export function readLicenseString(text) {
  const t = String(text).trim();
  if (!t) return { status: 'unknown', reason: 'missing' };
  if (/^UNLICEN[CS]ED$/i.test(t)) return { status: 'unknown', reason: 'unlicensed' };
  const see = /^SEE LICEN[CS]E IN\s+(\S.*)$/i.exec(t);
  if (see) return { status: 'unknown', reason: 'see-license-in', file: see[1] };
  try {
    return { status: 'ok', ...parseSpdx(text) };
  } catch (e) {
    if (!(e instanceof SpdxError)) throw e;
    return { status: 'unknown', reason: 'invalid', text, error: e.message, column: e.column };
  }
}

// A license value: a string, a legacy {type} object, or an array of either (OR).
// An unknown read says which item it is about (license, licenses[1], ...).
function readValue(v, field) {
  const typeOf = (o) => (typeof o.type === 'string' ? o.type : typeof o.name === 'string' ? o.name : null);
  const malformed = (f, item, value) => ({ field: f, raw: v, read: { status: 'unknown', reason: 'malformed', item, value } });
  if (typeof v === 'string') return { field, raw: v, read: { ...readLicenseString(v), item: field } };
  if (isObj(v)) {
    const t = typeOf(v);
    if (t === null) return malformed(field, field, v);
    return { field: `${field} (object)`, raw: v, read: { ...readLicenseString(t), item: `${field}.type` } };
  }
  if (Array.isArray(v)) {
    const name = field === 'license' ? 'license (array)' : field;
    const parts = [];
    for (let i = 0; i < v.length; i++) {
      const item = v[i];
      const t = typeof item === 'string' ? item : isObj(item) ? typeOf(item) : null;
      if (t === null) return malformed(name, `${field}[${i}]`, item);
      const r = readLicenseString(t);
      if (r.status !== 'ok') return { field: name, raw: v, read: { ...r, item: `${field}[${i}]` } };
      parts.push(r);
    }
    const node = joinNodes('or', parts.map((p) => p.node));
    return {
      field: name,
      raw: v,
      read: { status: 'ok', node, expression: renderNode(node), deprecated: [...new Set(parts.flatMap((p) => p.deprecated))], rewritten: parts.flatMap((p) => p.rewritten) },
    };
  }
  return malformed(field, field, v);
}

/**
 * The license of a manifest (a packument's version document): license,
 * falling back to the legacy licenses array when license is absent or empty.
 * @param {{license?: *, licenses?: *}} doc
 * @returns {{field: string|null, raw: *, read: object}} read as readLicenseString's,
 *   or reason 'malformed' for a field of the wrong type
 */
export function licenseOfManifest(doc) {
  if (!absent(doc?.license)) return readValue(doc.license, 'license');
  if (!absent(doc?.licenses)) return readValue(doc.licenses, 'licenses');
  return { field: null, raw: null, read: { status: 'unknown', reason: 'missing' } };
}

// ---------------------------------------------------------------------------
// The policy
// ---------------------------------------------------------------------------

/**
 * Reads allowed_licenses: SPDX license and exception identifiers (any case),
 * LicenseRef- and AdditionRef- identifiers (exactly). UsageError if bad.
 * @param {string} value separated by commas, spaces or newlines
 * @returns {{licenses: Set, refs: Set, exceptions: Set, additionRefs: Set, list: string[]}}
 */
export function parseAllowedLicenses(value) {
  const items = splitList(value);
  if (!items.length) {
    throw new UsageError('allowed_licenses is empty, so no package could pass. List the SPDX identifiers of the licenses packages may have, such as MIT,Apache-2.0.');
  }
  const policy = { licenses: new Set(), refs: new Set(), exceptions: new Set(), additionRefs: new Set(), list: [] };
  const add = (set, id) => { if (!set.has(id)) { set.add(id); policy.list.push(id); } };
  for (const item of items) {
    if (LICENSE_REF_RE.test(item)) { add(policy.refs, item); continue; }
    if (ADDITION_REF_RE.test(item)) { add(policy.additionRefs, item); continue; }
    const lic = lookupLicense(item);
    if (lic && GNU_BARE.has(lic.id)) {
      throw new UsageError(`allowed_licenses: ${lic.id} is a deprecated SPDX identifier, which this check reads as ${lic.id}-only `
        + `(and ${lic.id}+ as ${lic.id}-or-later). List ${lic.id}-only or ${lic.id}-or-later instead.`);
    }
    if (lic) { add(policy.licenses, lic.id); continue; }
    const exc = lookupException(item);
    if (exc) { add(policy.exceptions, exc.id); continue; }
    const base = item.endsWith('+') ? lookupLicense(item.slice(0, -1)) : null;
    if (base) {
      const instead = GNU_BARE.has(base.id) ? `${base.id}-or-later` : base.id;
      throw new UsageError(`allowed_licenses takes identifiers, not ${item}: list ${instead}, which allows ${item} too.`);
    }
    if (/^UNLICEN[CS]ED$/i.test(item)) {
      throw new UsageError('allowed_licenses: UNLICENSED means no license is granted, so it can\'t be allowed. Give a package you have '
        + 'rights to use a license with clarify, such as name=LicenseRef-Corp, and allow that.');
    }
    throw new UsageError(`allowed_licenses: ${show(item)} is not an identifier of the SPDX License List ${SPDX_LIST_VERSION}, nor a LicenseRef-.`);
  }
  return policy;
}

/**
 * Whether a parsed expression is allowed, and which of its terms keep it from
 * being allowed.
 * @param {object} node from parseSpdx
 * @param {object} policy from parseAllowedLicenses
 * @returns {{ok: boolean, bad: string[]}}
 */
export function judge(node, policy) {
  switch (node.type) {
    case 'license': {
      const ok = policy.licenses.has(node.id) || (node.id.endsWith('-or-later') && policy.licenses.has(`${node.id.slice(0, -9)}-only`));
      return { ok, bad: ok ? [] : [renderNode(node)] };
    }
    case 'ref': {
      const ok = policy.refs.has(node.id);
      return { ok, bad: ok ? [] : [node.id] };
    }
    case 'with': {
      const lic = judge(node.license, policy);
      const e = node.exception;
      const eok = e.ref ? policy.additionRefs.has(e.id) : policy.exceptions.size === 0 || policy.exceptions.has(e.id);
      return { ok: lic.ok && eok, bad: [...lic.bad, ...(eok ? [] : [`the exception ${e.id}`])] };
    }
    case 'and':
    case 'or': {
      const parts = node.args.map((a) => judge(a, policy));
      const ok = node.type === 'and' ? parts.every((p) => p.ok) : parts.some((p) => p.ok);
      return { ok, bad: ok ? [] : [...new Set(parts.flatMap((p) => p.bad))] };
    }
    default: throw new Error(`Internal error: a node of type ${show(node.type)}.`);
  }
}

/** Says why a denied expression isn't allowed. */
export function explainDenied(node, bad) {
  const list = bad.join(', ');
  if (node.type === 'or') return `none of its choices is in allowed_licenses (${list})`;
  return `${list} ${bad.length === 1 ? 'is' : 'are'} not in allowed_licenses`;
}

// ---------------------------------------------------------------------------
// clarify
// ---------------------------------------------------------------------------

/**
 * Reads clarify: lines name=EXPRESSION or name@version=EXPRESSION, name being
 * a package name or a pattern with * globs. Every expression must parse.
 * UsageError if bad.
 * @param {string[]} lines trimmed, without blank lines and comments
 * @returns {Array<{line, key, pattern, glob, version, expression, node, rank, used}>}
 */
export function parseClarify(lines) {
  const out = [];
  const seen = new Set();
  for (const line of lines) {
    const eq = line.indexOf('=');
    const key = eq > 0 ? line.slice(0, eq).trim() : '';
    const expr = eq > 0 ? line.slice(eq + 1).trim() : '';
    if (!key || !expr) throw new UsageError(`clarify takes lines name=EXPRESSION or name@version=EXPRESSION, such as busboy@1.6.0=MIT, not ${show(line)}.`);
    const pattern = compilePattern(key, { versions: true, param: 'clarify' });
    if (seen.has(pattern.text)) throw new UsageError(`clarify names ${pattern.text} twice.`);
    seen.add(pattern.text);
    let parsed;
    try { parsed = parseSpdx(expr); } catch (e) {
      if (!(e instanceof SpdxError)) throw e;
      const what = /^UNLICEN[CS]ED$/i.test(expr) || /^SEE LICEN[CS]E IN\b/i.test(expr) ? `${expr} names no license` : `${e.message} (column ${e.column} of the expression)`;
      throw new UsageError(`clarify: ${show(line)} doesn't give an SPDX expression: ${what}.`);
    }
    const gnu = parsed.rewritten.find((r) => GNU_BARE.has(r.from.replace(/\+$/, '')));
    if (gnu) throw new UsageError(`clarify: ${show(line)} uses ${gnu.from}, a deprecated SPDX identifier; write ${gnu.to} instead.`);
    const glob = pattern.name.includes('*');
    out.push({ line, key: pattern.text, pattern, glob, version: pattern.version, expression: parsed.expression, node: parsed.node,
      deprecated: parsed.deprecated, rank: (glob ? 0 : 2) + (pattern.version !== null ? 2 : 1), used: false });
  }
  return out;
}

/**
 * The clarification for NAME@VERSION: name@version over name, an exact name
 * over a glob, and the first line among equals.
 * @returns {object|null}
 */
export function findClarification(clarifications, name, version) {
  let best = null;
  for (const c of clarifications) {
    if (!c.pattern.re.test(name) || (c.version !== null && c.version !== version)) continue;
    if (!best || c.rank > best.rank) best = c;
  }
  return best;
}

// ---------------------------------------------------------------------------
// The command
// ---------------------------------------------------------------------------

const SKIP_REASONS = {
  git: 'a git dependency, which has no registry metadata',
  remote: 'a tarball from a URL, which has no registry metadata',
  local: 'a local directory or tarball (file:), which has no registry metadata',
  link: 'a linked directory (link:), which has no registry metadata',
  workspace: 'one of the project\'s own workspace packages',
};

const RULES = {
  'licenses/denied': { description: 'A package\'s license is not in allowed_licenses', tags: ['license'] },
  'licenses/unknown': { description: 'A package names no license the check can read: none, UNLICENSED, SEE LICENSE IN, or not SPDX', tags: ['license'] },
};

// Keeps only the license fields of the wanted versions of a packument.
function pickLicenses(doc, wanted) {
  const versions = isObj(doc.versions) ? doc.versions : null;
  const out = new Map();
  for (const v of wanted ?? []) {
    if (versions && Object.prototype.hasOwnProperty.call(versions, v) && isObj(versions[v])) {
      out.set(v, { license: versions[v].license, licenses: versions[v].licenses });
    }
  }
  return { versions: out };
}

// What a package is counted under in summary.licenses: its expression, or
// for an unknown license the value as written (a legacy object or array as
// its types).
function countKey(r) {
  if (r.license) return r.license;
  if (r.reason === 'not-on-registry') return '(not on the registry)';
  if (r.raw === null || r.raw === undefined) return '(none)';
  const brief = (v) => (isObj(v) && (typeof v.type === 'string' || typeof v.name === 'string') ? v.type ?? v.name : v);
  const v = Array.isArray(r.raw) ? r.raw.map(brief) : brief(r.raw);
  const s = typeof v === 'string' ? v.trim() : JSON.stringify(v);
  return s.length > 120 ? s.slice(0, 117) + '...' : s;
}

function unknownMessage(p, info, offline) {
  const nv = `${p.name}@${p.version}`;
  const read = info.read;
  const item = read.item ?? 'license';
  const where = offline ? ` in ${p.entries[0].lockfile}` : '';
  const which = item === 'license' ? '' : ` (${item})`;
  switch (read.reason) {
    case 'missing':
      return offline
        ? `${nv} has no license${where}: it names none, or only in the legacy licenses array, which npm leaves out of lockfiles. Check it without offline to read that array.`
        : `${nv} names no license: its registry metadata has neither license nor licenses.`;
    case 'unlicensed': return `${nv} is UNLICENSED${which}: its authors grant no license to use it.`;
    case 'see-license-in': return `${nv} says SEE LICENSE IN ${read.file}${which}: its terms are in a file, which this check doesn't read.`;
    case 'not-on-registry': return `${nv}: ${read.detail}. If it comes from another registry, map its scope to it with scopes.`;
    case 'malformed': return `${nv}: ${item}${where} is ${show(read.value)}, neither an SPDX expression nor a legacy {type} object.`;
    default: return `${nv}: ${item} ${show(read.text)}${where} is not an SPDX expression (${read.error}, column ${read.column}).`;
  }
}

/**
 * The licenses command (see the top of this file). ctx is core's context.
 * @param {object} ctx
 */
export async function run(ctx) {
  // Every parameter first: a bad one exits 2 before anything is read.
  const policy = parseAllowedLicenses(ctx.str('allowed_licenses', DEFAULT_ALLOWED_LICENSES));
  const clarifications = parseClarify(ctx.lines('clarify', ''));
  const offline = ctx.bool('offline', false);

  const set = ctx.readLockfiles();
  const errors = [];
  const warnings = [];
  const skipped = [];
  const unreadable = new Set();
  if (offline) {
    for (const l of set.lockfiles) {
      if (l.format === 'npm' && (l.formatVersion === '2' || l.formatVersion === '3')) continue;
      unreadable.add(l.rel);
      const what = l.format === 'npm' ? `an npm lockfile of version ${l.formatVersion}` : `a ${l.format} lockfile`;
      errors.push(`${l.rel} is ${what}, which records no licenses: offline needs npm lockfiles of version 2 or 3 `
        + '(package-lock.json or npm-shrinkwrap.json). Set offline to false to read licenses from the registry.');
    }
  }

  // Packages by registry and name@version (no registry offline), each with
  // its first entry in each lockfile.
  const packages = new Map();
  const seen = new Set();
  const skipWarnings = new Map(); // reason -> name@version of each package skipped for it
  const warnSkip = (reason, e) => skipWarnings.set(reason, [...(skipWarnings.get(reason) ?? []), `${e.name}@${e.version}`]);
  for (const e of set.entries) {
    if (unreadable.has(e.lockfile)) continue;
    let reason = null;
    let registry = null;
    if (e.kind !== 'registry') reason = SKIP_REASONS[e.kind] ?? `a ${e.kind} entry`;
    else if (!offline) ({ registry, reason } = metadataRegistry(e, ctx.registries));
    const key = `${registry ?? ''}\0${e.name}@${e.version ?? ''}`;
    const loc = `${e.lockfile}\0${e.kind}\0${key}`;
    if (seen.has(loc)) continue;
    seen.add(loc);
    if (reason) {
      skipped.push({ name: e.name, version: e.version, kind: e.kind, lockfile: e.lockfile, line: e.line, source: e.source, reason });
      if (e.kind === 'registry') warnSkip(reason, e);
      else if (e.kind === 'git' || e.kind === 'remote') warnSkip('packages from git or a tarball URL have no registry metadata', e);
      continue;
    }
    if (!packages.has(key)) packages.set(key, { name: e.name, version: e.version, registry, entries: [] });
    packages.get(key).entries.push(e);
  }

  // Clarifications, then each registry for the rest.
  const wanted = new Map(); // registry -> Map name -> Set of versions
  for (const p of packages.values()) {
    p.clarification = findClarification(clarifications, p.name, p.version);
    if (p.clarification) p.clarification.used = true;
    else if (!offline) {
      if (!wanted.has(p.registry)) wanted.set(p.registry, new Map());
      const names = wanted.get(p.registry);
      if (!names.has(p.name)) names.set(p.name, new Set());
      names.get(p.name).add(p.version);
    }
  }
  const docs = new Map(); // registry -> getPackuments' answers
  for (const [registry, names] of wanted) {
    docs.set(registry, await ctx.client.getPackuments([...names.keys()], { pick: (doc, name) => pickLicenses(doc, names.get(name)), registryFor: () => registry }));
  }

  const results = [];
  const findings = [];
  const failed = new Map();
  for (const p of [...packages.values()].sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : a.version < b.version ? -1 : a.version > b.version ? 1 : 0))) {
    let info;
    if (p.clarification) {
      const c = p.clarification;
      info = { field: 'clarify', raw: c.line, read: { status: 'ok', node: c.node, expression: c.expression, deprecated: c.deprecated, rewritten: [] } };
    } else if (offline) {
      const values = [...new Set(p.entries.map((e) => JSON.stringify(e.license)))];
      if (values.length > 1) warnings.push(`${p.name}@${p.version} has different licenses in different lockfiles (${values.join(', ')}); the first, from ${p.entries[0].lockfile}, is checked.`);
      const lic = p.entries[0].license;
      info = absent(lic) ? { field: 'lockfile', raw: null, read: { status: 'unknown', reason: 'missing' } } : { ...readValue(lic, 'license'), field: 'lockfile' };
    } else {
      const registry = p.registry;
      const r = docs.get(registry).get(p.name);
      const unauthorized = r && unauthorizedSkip(registry, r.status, ctx.registries);
      if (unauthorized) {
        for (const e of p.entries) skipped.push({ name: p.name, version: p.version, kind: e.kind, lockfile: e.lockfile, line: e.line, source: e.source, reason: unauthorized });
        warnSkip(unauthorized, p);
        continue;
      }
      if (r?.packument) {
        const v = r.packument.versions.get(p.version);
        info = v ? licenseOfManifest(v)
          : { field: null, raw: null, read: { status: 'unknown', reason: 'not-on-registry', detail: `${registry} lists no version ${p.version} of ${p.name}` } };
      } else if (r?.status === 404) {
        info = { field: null, raw: null, read: { status: 'unknown', reason: 'not-on-registry', detail: `${registry} has no package ${p.name} (HTTP 404)` } };
      } else {
        const why = r?.error ?? `HTTP ${r?.status ?? 0}`;
        const k = `${registry}\0${why}`;
        if (!failed.has(k)) failed.set(k, { registry, why, status: r?.status ?? 0, names: [] });
        failed.get(k).names.push(`${p.name}@${p.version}`);
        continue;
      }
    }
    const read = info.read;
    const result = { name: p.name, version: p.version, registry: p.registry, status: null, license: null, field: info.field, raw: info.raw ?? null };
    let finding = null;
    if (read.status === 'ok') {
      result.license = read.expression;
      if (read.deprecated.length) result.deprecated_ids = read.deprecated;
      const verdict = judge(read.node, policy);
      if (verdict.ok) result.status = 'allowed';
      else {
        result.status = 'denied';
        result.not_allowed = verdict.bad;
        finding = { kind: 'denied', message: `${p.name}@${p.version} is licensed ${read.expression}: ${explainDenied(read.node, verdict.bad)}.` };
      }
    } else {
      result.status = 'unknown';
      result.reason = read.reason;
      finding = { kind: 'unknown', message: unknownMessage(p, info, offline) };
    }
    if (p.clarification) result.clarified_by = p.clarification.line;
    result.lockfiles = [...new Set(p.entries.map((e) => e.lockfile))];
    results.push(result);
    if (finding) {
      const details = { license: result.license, raw: result.raw, field: result.field };
      if (result.reason) details.reason = result.reason;
      if (result.not_allowed) details.not_allowed = result.not_allowed;
      if (result.deprecated_ids) details.deprecated_ids = result.deprecated_ids;
      for (const e of p.entries) {
        const extra = e.alias ? { ...details, alias: e.alias } : details;
        findings.push(ctx.finding(e, { kind: finding.kind, message: finding.message, details: extra }));
      }
    }
  }

  for (const f of failed.values()) {
    const shown = f.names.slice(0, 5).join(', ') + (f.names.length > 5 ? `, and ${f.names.length - 5} more` : '');
    let msg = `Could not read the registry metadata of ${plural(f.names.length, 'package')} (${shown}) from ${publicUrl(f.registry)}: ${f.why}.`;
    if (f.status === 401 || f.status === 403) msg += ` ${authHint(ctx.tokenVar)}`;
    errors.push(msg);
  }
  for (const [reason, names] of skipWarnings) warnings.push(skipWarning(names, 'checked', reason));
  for (const c of clarifications) if (!c.used) warnings.push(`clarify: ${show(c.line)} matches no package whose license this check reads, so it is unused.`);

  const by = (status) => results.filter((r) => r.status === status).length;
  const licenseCounts = new Map();
  for (const r of results) licenseCounts.set(countKey(r), (licenseCounts.get(countKey(r)) ?? 0) + 1);
  // An array, since an object would put keys such as "42" first.
  const licenses = [...licenseCounts].sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0)).map(([license, packages]) => ({ license, packages }));
  const unknownReasons = {};
  for (const r of results) if (r.status === 'unknown') unknownReasons[r.reason] = (unknownReasons[r.reason] ?? 0) + 1;
  const counts = { packages: results.length, allowed: by('allowed'), denied: by('denied'), unknown: by('unknown'), clarified: results.filter((r) => r.clarified_by).length, skipped: skipped.length };

  const { io } = ctx;
  const clarified = counts.clarified ? ` (${counts.clarified} clarified)` : '';
  io.log(`Read the licenses of ${plural(results.length, 'package')} from ${offline ? 'the lockfiles' : 'the registry'}${clarified}: `
    + `${counts.allowed} allowed, ${counts.denied} denied, ${counts.unknown} unknown; ${skipped.length} not checked.`
    + `${errors.length ? ' The check is incomplete (see the errors), so it has no verdict.' : ''}`);
  for (const l of licenses) io.log(`  ${String(l.packages).padStart(6)}  ${l.license}`);
  if (counts.unknown) io.log('Once you know the license of a package whose license is unknown, set it with clarify, such as name@version=MIT.');

  return {
    findings,
    errors,
    warnings,
    skipped,
    checked: results.length,
    rules: RULES,
    results,
    counts,
    summary: {
      source: offline ? 'lockfile' : 'registry',
      spdx_license_list: SPDX_LIST_VERSION,
      allowed_licenses: policy.list,
      ...counts,
      licenses,
      unknown_reasons: unknownReasons,
    },
  };
}

// Runs the command when this file is the program (node helper/licenses.mjs),
// not when a test imports it.
if (isMain(import.meta.url)) await main('licenses', run);
