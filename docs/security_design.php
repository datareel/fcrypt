<?php
  // File encryption utility (fcrypt) security design white paper (new layout), 11/18/2026.
  // Written from the fcrypt 2026.109 source (include/fcfile.h, src/fcfile.cpp, src/fcfips.cpp,
  // src/fckeymgmt.cpp, src/smart_card.cpp, src/rsadb.cpp, src/cryptdb.cpp, console/*.cpp) and
  // README.txt; update it when the file format or the cryptography changes.
  require_once $_SERVER['DOCUMENT_ROOT'] . '/php/dr2_layout.php';
  if ($dr2_classic = dr2_classic_page(__FILE__)) { include $dr2_classic; exit; }
  $dr2_t = 'File Encryption (fcrypt) security design';
  $dr2_d = 'How fcrypt protects files: the 2026102 file format, per-file keys wrapped for passwords, key files, RSA keys and smart cards, AES-256-CBC with HMAC-SHA256 on every record, FIPS 140-3 mode, key management, the access log, the security measures and their limits.';
  $PageTitle = $dr2_t . ' | DataReel Software Development';
  $PageDescription = $dr2_d;
  $CALLER_HAS_CSS_LINK = '/css/dr2_docs.css';
  include $_SERVER['DOCUMENT_ROOT'] . '/php/dr2_all_pages_header.php';
  echo dr2_page_head(array('Home' => '/index.php', 'File Encryption' => '/info_fcrypt.php', 'Security design' => NULL), 'White paper', $dr2_t, $dr2_d);
?>
<style>
.fc-fig { margin: 18px 0 26px; overflow-x: auto; }
.fc-fig svg { display: block; width: 100%; max-width: 860px; height: auto; min-width: 560px; }
.fc-fig figcaption { color: var(--dr2-muted); font-size: 14px; margin-top: 6px; }
.fc-fig .b { fill: var(--dr2-surface-2); stroke: var(--dr2-border-strong); stroke-width: 1.5; }
.fc-fig .k { fill: var(--dr2-accent-soft); stroke: var(--dr2-accent); stroke-width: 1.5; }
.fc-fig text { fill: var(--dr2-text); font: 14px system-ui, -apple-system, "Segoe UI", sans-serif; }
.fc-fig text.s { fill: var(--dr2-muted); font-size: 12px; }
.fc-fig .a { stroke: var(--dr2-muted); stroke-width: 1.5; fill: none; marker-end: url(#fc-arrow); }
.fc-fig marker path { fill: var(--dr2-muted); }
.fc-table { overflow-x: auto; }
</style>
<article class="dr2-doc">

<p><b>Release:</b> 2026.109 (file format 2026102), built with the DataReel C++ library 6.4.1.
<b>Audience:</b> security reviewers, administrators and anyone deciding whether to trust fcrypt with their
files. The source code is published, so everything on this page can be checked against it; the design does
not depend on keeping it secret. The <a href="/fcrypt/index.php">README</a> has the commands, and the
programs are on the <a href="/downloads/index.php#fcrypt">downloads page</a>.</p>

<h2 id="overview">1. What fcrypt protects, and from whom</h2>
<p>fcrypt encrypts a file into a <code>.enc</code> file, fdecrypt decrypts it, and fmigrate converts files
from older releases to the current format. The goals are:</p>
<ul>
<li><b>Confidentiality at rest:</b> someone who copies an encrypted file, a backup or a lost disk cannot read
the data or the original file name without a credential that opens the file.</li>
<li><b>Integrity:</b> a change made to the encrypted file, such as changed, removed, reordered, added or
truncated data, or a changed list of users, is detected before any decrypted output is kept.</li>
<li><b>Separate credentials per person:</b> a file can be opened with a password or key file, and by several
people with their own RSA key, SSH-RSA key or smart card. One user can be removed, and the file given a new
key, without sharing a new secret with the rest.</li>
<li><b>No secrets in scripts:</b> passwords, passphrases and PINs can be read from a private file or a file
descriptor instead of the command line.</li>
<li><b>No damaged files:</b> decrypting, removing a user, rekeying and converting write a new file and check
it before it replaces anything.</li>
</ul>
<p>fcrypt does not protect against an attacker who controls the computer while a file is being encrypted or
decrypted (malware that reads the program's memory, the keyboard or the decrypted output), against a weak
password, or against someone who already has a valid credential.</p>

<h2 id="format">2. The 2026102 file format</h2>
<p>fcrypt writes only format 2026102 (release 2026.102 and later). All integers are little endian. A file is
a fixed header, a key slot area, a header MAC and a series of encrypted records.</p>
<figure class="fc-fig">
<svg viewBox="0 0 860 250" role="img" aria-label="File layout: a 128-byte fixed header, the key slot area, a 32-byte header MAC, record 0 with the stored file name, then records 1 to N with up to 64 KB of data each. Each record is a 4-byte ciphertext length, a 16-byte IV, the ciphertext and a 32-byte HMAC-SHA256 tag.">
<defs><marker id="fc-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z"/></marker></defs>
<rect class="b" x="10" y="20" width="150" height="64" rx="8"/><text x="85" y="48" text-anchor="middle">Fixed header</text><text class="s" x="85" y="66" text-anchor="middle">128 bytes, clear</text>
<rect class="b" x="170" y="20" width="190" height="64" rx="8"/><text x="265" y="48" text-anchor="middle">Key slot area</text><text class="s" x="265" y="66" text-anchor="middle">16,384 bytes by default</text>
<rect class="k" x="370" y="20" width="110" height="64" rx="8"/><text x="425" y="48" text-anchor="middle">Header MAC</text><text class="s" x="425" y="66" text-anchor="middle">32 bytes</text>
<rect class="b" x="490" y="20" width="130" height="64" rx="8"/><text x="555" y="48" text-anchor="middle">Record 0</text><text class="s" x="555" y="66" text-anchor="middle">stored file name</text>
<rect class="b" x="630" y="20" width="220" height="64" rx="8"/><text x="740" y="48" text-anchor="middle">Records 1 to N</text><text class="s" x="740" y="66" text-anchor="middle">up to 64 KB of data each</text>
<path class="a" d="M555,84 C555,120 300,110 260,148"/><path class="a" d="M740,84 C740,120 640,115 620,148"/>
<rect class="b" x="60" y="150" width="130" height="56" rx="8"/><text x="125" y="174" text-anchor="middle">Length</text><text class="s" x="125" y="192" text-anchor="middle">4 bytes</text>
<rect class="b" x="200" y="150" width="130" height="56" rx="8"/><text x="265" y="174" text-anchor="middle">IV</text><text class="s" x="265" y="192" text-anchor="middle">16 bytes, random</text>
<rect class="b" x="340" y="150" width="250" height="56" rx="8"/><text x="465" y="174" text-anchor="middle">Ciphertext</text><text class="s" x="465" y="192" text-anchor="middle">AES-256-CBC, PKCS#7 padding</text>
<rect class="k" x="600" y="150" width="200" height="56" rx="8"/><text x="700" y="174" text-anchor="middle">Tag</text><text class="s" x="700" y="192" text-anchor="middle">HMAC-SHA256, 32 bytes</text>
<text class="s" x="430" y="235" text-anchor="middle">The tag covers the file ID, the record number, a last-record flag, the length, the IV and the ciphertext.</text>
</svg>
<figcaption>Figure 1. Layout of a 2026102 file and of one record.</figcaption>
</figure>
<div class="fc-table">
<table>
<tr><td><b>Part</b></td><td><b>Contents</b></td></tr>
<tr><td>Fixed header (128 bytes)</td><td>Magic <code>FCRYPT\x1A\x04</code>, file version 2026102, header length, flags,
KDF ID (1 = PBKDF2-HMAC-SHA256), KDF iteration count, cipher ID (1 = AES-256-CBC with HMAC-SHA256,
encrypt-then-MAC), chunk size (65,536), key slot area length, a random 32-byte PBKDF2 salt, a random 16-byte
file ID and 40 reserved bytes. A file that was rekeyed keeps its key generation and rekey time in the
reserved bytes.</td></tr>
<tr><td>Key slot area</td><td>One slot per way of opening the file: type (1 = password or key file, 2 = RSA key,
3 = smart card), slot length, user name and the wrapped file key. Unused space is zero. The area is 2,048 to
65,535 bytes, 16,384 by default.</td></tr>
<tr><td>Header MAC (32 bytes)</td><td>HMAC-SHA256 over the fixed header and the whole key slot area.</td></tr>
<tr><td>Records</td><td>Record 0 holds the stored file name; records 1 to N hold the file data, one chunk of up
to 65,536 bytes each. Each record is encrypted and tagged on its own (section 4).</td></tr>
</table>
</div>
<p>When a file is opened, every header value and every slot length is checked against fixed limits before it
is used (for example the iteration count must be 1,000 to 10,000,000 and a user name at most 255 bytes),
because none of it is authenticated until a credential has recovered the file key.</p>

<h2 id="keys">3. The file key and the key slots</h2>
<p>Every file has its own random 256-bit <b>file key</b>, made by the OpenSSL random generator. Every
credential is a way to recover that file key, and the file key is never stored in the clear.</p>
<figure class="fc-fig">
<svg viewBox="0 0 860 330" role="img" aria-label="Key slots: a password or key file goes through PBKDF2 and AES-256 Key Wrap; an RSA or SSH-RSA public key and a smart card certificate wrap the file key with RSA-OAEP SHA-256; the file key derives the header MAC key, the data encryption key and the data MAC key with KBKDF.">
<rect class="b" x="10" y="20" width="200" height="56" rx="8"/><text x="110" y="44" text-anchor="middle">Password or key file</text><text class="s" x="110" y="62" text-anchor="middle">slot type 1, at most one</text>
<rect class="b" x="10" y="110" width="200" height="56" rx="8"/><text x="110" y="134" text-anchor="middle">RSA or SSH-RSA key</text><text class="s" x="110" y="152" text-anchor="middle">slot type 2, one per user</text>
<rect class="b" x="10" y="200" width="200" height="56" rx="8"/><text x="110" y="224" text-anchor="middle">Smart card (PKCS#11)</text><text class="s" x="110" y="242" text-anchor="middle">slot type 3, one per user</text>
<rect class="b" x="250" y="20" width="220" height="56" rx="8"/><text x="360" y="44" text-anchor="middle">PBKDF2 + AES Key Wrap</text><text class="s" x="360" y="62" text-anchor="middle">600,000 rounds, 32-byte salt</text>
<rect class="b" x="250" y="155" width="220" height="56" rx="8"/><text x="360" y="179" text-anchor="middle">RSA-OAEP, SHA-256</text><text class="s" x="360" y="197" text-anchor="middle">RSA user keys 2048 bits or more</text>
<rect class="k" x="510" y="85" width="140" height="64" rx="8"/><text x="580" y="113" text-anchor="middle">File key</text><text class="s" x="580" y="131" text-anchor="middle">256-bit, random</text>
<rect class="b" x="700" y="30" width="150" height="44" rx="8"/><text x="775" y="57" text-anchor="middle">Header MAC key</text>
<rect class="b" x="700" y="95" width="150" height="44" rx="8"/><text x="775" y="122" text-anchor="middle">Data encryption</text>
<rect class="b" x="700" y="160" width="150" height="44" rx="8"/><text x="775" y="187" text-anchor="middle">Data MAC</text>
<text class="s" x="580" y="190" text-anchor="middle">KBKDF-HMAC-SHA256</text><text class="s" x="580" y="206" text-anchor="middle">context: file ID</text>
<path class="a" d="M210,48 L248,48"/><path class="a" d="M470,48 C495,48 495,100 508,104"/>
<path class="a" d="M210,138 C230,138 230,175 248,178"/><path class="a" d="M210,228 C230,228 230,195 248,192"/>
<path class="a" d="M470,183 C495,183 495,135 508,130"/>
<path class="a" d="M650,105 C675,105 675,52 698,52"/><path class="a" d="M650,117 L698,117"/>
<path class="a" d="M650,130 C675,130 675,182 698,182"/>
<text class="s" x="430" y="300" text-anchor="middle">--remove-user deletes a slot; --rekey makes a new file key and rewraps every kept user.</text>
</svg>
<figcaption>Figure 2. Every credential recovers the same file key; three working keys are derived from it.</figcaption>
</figure>
<ul>
<li><b>Password or key file:</b> PBKDF2-HMAC-SHA256 (SP 800-132) with the file's random 32-byte salt turns the
password, or the contents of a key file, into a 256-bit key that wraps the file key with AES-256 Key Wrap
(SP 800-38F). The default is 600,000 iterations; <code>fcrypt --iter</code> accepts 1,000 to 10,000,000, and
the count is stored in the header. A password or key must be at least 8 bytes. Key Wrap has its own integrity
check, so a wrong password is found when the key is unwrapped.</li>
<li><b>RSA and SSH-RSA keys:</b> the file key is encrypted to the user's RSA public key with RSA-OAEP, using
SHA-256 for both the hash and MGF1. Adding a user needs only their public key (an SSH-RSA key is converted
to a PEM public key with ssh-keygen). fcrypt refuses an RSA user key under 2048 bits; slots hold RSA keys
up to 8192 bits. The user decrypts with their private key file.</li>
<li><b>Smart cards:</b> the file key is encrypted with RSA-OAEP SHA-256 to the public key of a card
certificate, read from the card (no PIN) or from an exported certificate file. The card decrypts it with a
private key that never leaves the card (section 7).</li>
<li><b>Derived keys:</b> KBKDF in counter mode with HMAC-SHA256 (SP 800-108) derives three keys from the file
key, each with its own label and the file ID as context: the header MAC key, the data encryption key and the
data MAC key. No key is used for two purposes.</li>
<li><b>Random values:</b> the file key, salt, file ID and every IV come from the OpenSSL random generator (the
FIPS provider's generator in FIPS mode).</li>
</ul>

<h2 id="records">4. Record encryption and integrity</h2>
<ul>
<li>Each record is encrypted with AES-256 in CBC mode under the data encryption key, with a new random 16-byte
IV. A record holds at most one chunk, 65,536 bytes, of data.</li>
<li>Each record then gets an HMAC-SHA256 tag under the data MAC key (encrypt-then-MAC). The tag covers the
file ID, the record's number (8 bytes), a last-record flag (1 byte), the ciphertext length, the IV and the
ciphertext. The tag is checked, in constant time, before the record is decrypted, so a changed ciphertext is
never decrypted.</li>
<li><b>Header authentication:</b> the header MAC covers the fixed header, including the iteration count, salt,
file ID and reserved bytes, and the whole key slot area. It is checked right after the file key is
recovered and before any record is read, so users cannot be added, removed or changed, and header values
cannot be altered, without a credential that opens the file.</li>
</ul>
<p>What the checks detect:</p>
<ul>
<li><b>Changed data:</b> any changed byte in a record fails its tag; a changed header or slot fails the header
MAC.</li>
<li><b>Removed or reordered records:</b> the record number is part of the tag, so a record in the wrong place
fails.</li>
<li><b>Truncated files:</b> only the final record carries the last-record flag. A file cut short ends on a
record without it and fails.</li>
<li><b>Added data:</b> a record followed by more bytes must not have the last-record flag, so data appended
after the real last record makes that record fail.</li>
<li><b>Records from another file:</b> the file ID is part of the tag, and each file has its own keys.</li>
<li><b>Bad lengths:</b> a record length that is not a whole number of AES blocks, or larger than a chunk plus
padding, is refused before anything is read into memory.</li>
</ul>

<h2 id="decrypt">5. Decryption and output files</h2>
<figure class="fc-fig">
<svg viewBox="0 0 860 300" role="img" aria-label="Decrypt flow: read the header and key slots and check every length; recover the file key from one slot; derive the keys and check the header MAC; check each record tag and decrypt it into a private temp file; after the last record, rename the temp file to the output name. Any failure removes the temp file and nothing is kept.">
<rect class="b" x="10" y="20" width="190" height="64" rx="8"/><text x="105" y="48" text-anchor="middle">1. Read header, slots</text><text class="s" x="105" y="66" text-anchor="middle">every length checked</text>
<rect class="b" x="225" y="20" width="190" height="64" rx="8"/><text x="320" y="48" text-anchor="middle">2. Unwrap file key</text><text class="s" x="320" y="66" text-anchor="middle">one credential, one slot</text>
<rect class="b" x="440" y="20" width="190" height="64" rx="8"/><text x="535" y="48" text-anchor="middle">3. Check header MAC</text><text class="s" x="535" y="66" text-anchor="middle">header and all slots</text>
<rect class="b" x="655" y="20" width="195" height="64" rx="8"/><text x="752" y="48" text-anchor="middle">4. Each record</text><text class="s" x="752" y="66" text-anchor="middle">check tag, then decrypt</text>
<rect class="b" x="440" y="130" width="190" height="64" rx="8"/><text x="535" y="158" text-anchor="middle">Private temp file</text><text class="s" x="535" y="176" text-anchor="middle">new, mode 600 on Linux</text>
<rect class="k" x="655" y="130" width="195" height="64" rx="8"/><text x="752" y="158" text-anchor="middle">5. Rename to output</text><text class="s" x="752" y="176" text-anchor="middle">only after the last record</text>
<rect class="b" x="10" y="130" width="300" height="64" rx="8"/><text x="160" y="158" text-anchor="middle">Any failure</text><text class="s" x="160" y="176" text-anchor="middle">temp file removed, error, non-zero exit</text>
<path class="a" d="M200,52 L223,52"/><path class="a" d="M415,52 L438,52"/><path class="a" d="M630,52 L653,52"/>
<path class="a" d="M752,84 C752,110 600,105 560,128"/><path class="a" d="M630,162 L653,162"/>
<path class="a" d="M440,175 L312,175"/>
<text class="s" x="430" y="240" text-anchor="middle">An existing output file is replaced only with -o. Stored paths with .. are refused, and leading /,</text>
<text class="s" x="430" y="258" text-anchor="middle">drive letters and UNC prefixes are removed unless --absolute-path is given.</text>
</svg>
<figcaption>Figure 3. Decrypted data is kept only after every check passes.</figcaption>
</figure>
<ul>
<li>fdecrypt writes decrypted data to a new temp file with a random name next to the output file. It is
created exclusively, never through a symbolic link, readable and writable only by the owner on Linux.</li>
<li>The temp file is renamed to the output name only after every record, including the one with the
last-record flag, has passed its check. If anything fails, the temp file is removed and nothing is left
behind. Without <code>-o</code> the rename fails rather than replace a file that appeared in the meantime.</li>
<li>The stored file name is not trusted. By default it is restored relative to the current or output
folder; names with <code>..</code> are refused. <code>--no-path</code> keeps only the file name and
<code>--absolute-path</code> restores the exact stored path, for full restores.</li>
<li>With <code>--stdout</code> there is no temp file: each record is written as soon as it passes its check, and
a failure stops the output with an error and a non-zero exit code (see section 12).</li>
<li>Keys, key encryption keys, unwrapped keys and decrypted buffers are cleared with
<code>OPENSSL_cleanse</code> once they are no longer needed.</li>
</ul>

<h2 id="fips">6. FIPS 140-3 mode</h2>
<p>fcrypt, fdecrypt and fmigrate have a FIPS 140-3 mode using the OpenSSL FIPS provider. fcrypt itself is not
a validated cryptographic module.</p>
<ul>
<li><b>When it is on:</b> with <code>--fips</code>, when <code>FCRYPT_FIPS=1</code> is set, or when the host is
in FIPS mode: <code>/proc/sys/crypto/fips_enabled</code> is 1 on Linux, the Windows "System cryptography: Use
FIPS compliant algorithms" policy is enabled, or the OpenSSL configuration sets <code>fips=yes</code>.
<code>--no-fips</code> turns it off for one run. <code>fcrypt --version</code> shows the mode and the provider
in use.</li>
<li><b>How:</b> the programs make their own OpenSSL library context with only the <code>fips</code> and
<code>base</code> providers loaded and <code>fips=yes</code> as the default property, and set
<code>fips=yes</code> in OpenSSL's default context too, for the few calls that always use it. If the FIPS
provider cannot be loaded or fails its self-test, the program stops and nothing is encrypted or
decrypted.</li>
<li><b>Algorithms:</b> format 2026102 uses only PBKDF2-HMAC-SHA256, AES-256 Key Wrap, RSA-OAEP with SHA-256,
KBKDF with HMAC-SHA256, AES-256-CBC and HMAC-SHA256, all fetched from that library context.</li>
<li><b>Refused in FIPS mode:</b> files from releases before 2026.102, whose key derivation is not an approved
algorithm; decrypt them with <code>fdecrypt --no-fips</code> or convert them with <code>fmigrate
--no-fips</code>. A private RSA key with a passphrase in the traditional PEM format, which derives its key
with MD5, cannot be read; convert it to PKCS#8 (the README shows the command, also for SSH-RSA keys).</li>
<li><b>Requirements:</b> FIPS mode needs OpenSSL 3.0 or later. RHEL 9 and 10 use the operating system's FIPS
provider (<code>fips-mode-setup --enable</code>). RHEL 8 has OpenSSL 1.1.1 without a FIPS provider: its builds
refuse <code>--fips</code> and run outside FIPS mode on a host in FIPS mode. Windows builds use the FIPS
provider (<code>fips.dll</code>) of the OpenSSL 3.5.x LTS release they were built with.</li>
<li><b>Compliance:</b> for FIPS 140-3 compliance the FIPS provider version in use must have a CMVP
certificate. Check the provider version against the validated list before relying on FIPS mode, and check
your site's policy with your security office.</li>
<li><b>Smart cards:</b> the card's private key operation is done by the card and its PKCS#11 module, not by the
OpenSSL FIPS provider (section 7).</li>
</ul>

<h2 id="smartcard">7. Smart cards (PKCS#11)</h2>
<ul>
<li><b>No OpenSSL engine on OpenSSL 3:</b> builds that use OpenSSL 3 (RHEL 9, RHEL 10 and Windows) load the
card's PKCS#11 module directly; the deprecated OpenSSL ENGINE API and the pkcs11 engine are not used. RHEL 8
builds (OpenSSL 1.1.1) still use the pkcs11 engine. The default module is OpenSC; on Windows the ActivClient
module is used when it is installed. <code>--smartcard-provider</code> picks another module.</li>
<li><b>Adding a card user</b> needs no PIN: the public key is read from the card or from an exported
certificate file, and the file key is wrapped in software with RSA-OAEP SHA-256. The card key must be RSA;
EC keys are refused, because they cannot decrypt a wrapped key.</li>
<li><b>Decrypting</b> asks the card to decrypt the wrapped key with RSA-OAEP SHA-256. Cards that cannot do
that themselves, such as PIV cards and ActivClient, decrypt with raw RSA on the card, and fcrypt removes the
OAEP padding (SHA-256, MGF1-SHA256), checking every byte before it reports a single padding error.</li>
<li><b>PIN safeguards</b> (CAC and PIV cards lock after three wrong PINs):
  <ul>
  <li>The PIN is sent to the card once per decrypt and never retried. After any failed card login, no more
  logins are made until the program is run again, not for the next file and not by any fallback.</li>
  <li>The PIN is not sent when it is empty, too long (it is never cut short), has a control character such as
  a tab or carriage return, or is outside the PIN length the card reports.</li>
  <li>The card's PIN flags are read before each login. A locked PIN is refused. When the card reports one try
  left or low tries, the PIN is sent only with <code>--smartcard-allow-final-try</code> or
  <code>--smartcard-allow-pin-count-low</code>. Some modules do not report the PIN tries, so passing these
  checks is not a promise that tries are left.</li>
  <li>After a wrong PIN the error says one try was used and what the card reports about the tries left.</li>
  </ul></li>
<li><b>Choosing the card:</b> <code>--smartcard-slot</code> uses only one PKCS#11 slot. Without it, a cert ID
found on more than one inserted card, or on none, is refused and no PIN is sent.</li>
<li><b>Listing without a PIN:</b> <code>fcrypt --smartcard-list</code> shows the cards, cert IDs, key types
and sizes and PIN status, and <code>--smartcard-match</code> finds the card that holds a certificate, using only
public PKCS#11 calls: no login, no PIN.</li>
</ul>

<h2 id="keymgmt">8. Removing users and rekeying</h2>
<ul>
<li><b><code>--remove-user</code></b> deletes the RSA key or smart card slot of one user. The last slot is never
removed. Removing a user does not change the file key, so a user who already recovered it could still use
it; the follow-up is <code>--rekey</code>.</li>
<li><b><code>--rekey</code></b> gives the file a new random file key, a new salt and a new file ID, encrypts every
record again and rewraps the key for every slot that is kept. RSA and smart card slots are rewrapped with
their public keys, so no card login is needed. Every existing slot needs a choice (keep, change or drop) in
the rekey input, or the rekey stops and lists what is missing; nothing is dropped silently, and a rekey that
would leave no slot is refused. The password slot can be kept, changed, dropped or given a generated
random password (64 hex digits) written to a private file or descriptor.</li>
<li><b>Atomic, checked rewrite:</b> both write a new temp file, decrypt it again and compare a keyed
HMAC-SHA256 of its data with the original's (for a rekey, also open it with the new password), flush it to
disk and only then rename it over the original. A crash or kill before the rename leaves the original as it
was. A backup copy, <code>name.backup-YYYYMMDD-HHMMSS.enc</code>, is kept. <code>--dry-run</code> writes and
checks the new file, then removes it.</li>
<li><b>One writer:</b> both take an advisory lock on <code>file.lock</code> (flock on Linux, LockFileEx on
Windows) and wait up to <code>--lock-timeout</code> seconds, 10 by default, for another writer.</li>
<li>Key management can be authenticated with the password or key file, with an RSA private key, or with a
smart card (one card login, with the PIN safeguards above).</li>
</ul>

<h2 id="secrets">9. Passwords, keys and prompts</h2>
<ul>
<li><b>Secrets from files and descriptors:</b> <code>--password-file</code>, <code>--password-fd</code>,
<code>--rsa-key-passphrase-file</code>, <code>--rsa-key-passphrase-fd</code>, <code>--smartcard-pin-file</code> and
<code>--smartcard-pin-fd</code> in fcrypt, fdecrypt and fmigrate. The secret is the first line, at most 4,096
bytes. On Linux the file must be a regular file, not a symbolic link, owned by you with no group or other
access. The buffers are wiped after use.</li>
<li><b>Secrets on the command line:</b> <code>--password=</code>, <code>--rsa-key-passphrase=</code> and
<code>--smartcard-pin=</code> still work, but print a warning and are overwritten in the process arguments
after they are read.</li>
<li><b>Key files:</b> on Linux a <code>--key</code> file or a private <code>--rsa-key</code> file must be a
regular file owned by you with no group or other access, as ssh requires for private keys; otherwise it is
refused.</li>
<li><b>Prompts:</b> typed passwords, passphrases and PINs are not shown; the <code>*</code> echo goes to stderr,
not stdout, so it is never mixed with output. A new password is asked for twice. A prompt that gets empty
input is an error, and <code>--non-interactive</code> makes a missing secret an error instead of a
prompt.</li>
<li><b>Scripts:</b> errors go to stderr and the exit codes are fixed: 0 ok, 1 usage or other error, 2 the
credential did not open the file, 3 file or user not found, 4 locked by another writer, 5
<code>--check-version</code> found an old file, 7 read or write error.</li>
</ul>

<h2 id="accesslog">10. Tamper-evident access log</h2>
<ul>
<li>Optional and off unless asked for: <code>--access-log[=file]</code> logs decrypts, user changes and rekeys
to a per-user log, by default <code>~/.fcrypt/logs/access.log</code> (folder mode 700, file mode 600).</li>
<li>Each entry has the UTC time, OS user, host, process ID, program, file path, file ID, credential type, slot
user, action and result. No password, PIN or file content is ever logged.</li>
<li>Entries are chained with HMAC-SHA256 per file ID, keyed with a key derived from the file key
(KBKDF-HMAC-SHA256), so an entry cannot be changed, removed, reordered or inserted without
<code>fdecrypt --verify-access-log</code> noticing, unless the person has the file key. Entries written without
the key, such as a failed decrypt, are covered by the next tagged entry. After a rekey the old entries are
checked with the old key and tagged again with the new one.</li>
<li>If the log cannot be written, the programs warn once and go on: a log failure never stops a decrypt or a
change.</li>
</ul>

<h2 id="compat">11. Older files, builds and platforms</h2>
<ul>
<li><b>Reading older files:</b> fdecrypt decrypts files from every earlier release outside FIPS mode.
Formats 2023102 and 2023103 derive their key with EVP_BytesToKey and SHA-256 (1,000 iterations by default)
and were checked block by block; files from 2025.105 on also carry a whole-file check.
<code>fdecrypt --check-version</code> reports each file's format without decrypting it.</li>
<li><b>Converting with fmigrate:</b> the old file is decrypted in memory and encrypted again as it is read, so
the plaintext is never written to disk. The new file is written to a private temp file, decrypted again and
checked against a SHA-256 hash of the data before it replaces the old file. RSA and smart card users of the
old file cannot be carried over, because the old file holds only their wrapped key, not their public key;
fmigrate lists them so they can be added again.</li>
<li><b>Older releases:</b> they have security problems and are no longer offered for download; only release
2026.109 is.</li>
<li><b>Linux:</b> RHEL 8, 9 and 10 (RHEL 10 is the default build), using the operating system's OpenSSL: release 2026.109 is built with OpenSSL 3.5.8 on RHEL 10, 3.5.9 on RHEL 9 and 1.1.1k on RHEL 8. The next release, 2026.110, is built with OpenSSL 3.5 LTS on every platform, with one exception: RHEL 8 hosts in FIPS mode get a build on Red Hat's FIPS-validated system OpenSSL 1.1.1k (RHEL 8's OpenSSL 3.5 packages come from EPEL, not Red Hat, and have no FIPS provider); other RHEL 8 hosts get a build with OpenSSL 3.5 LTS built in, and the installer picks the build by the host's FIPS mode.</li>
<li><b>Windows:</b> Windows 11, Windows Server 2022 and Windows Server 2025, 64-bit by default with a 32-bit
build kept for legacy systems. Windows builds use only an OpenSSL 3.5.x LTS release, built from source with
its FIPS provider; the build stops with an error for any other OpenSSL version. The 32-bit and 64-bit builds
write the same format.</li>
<li><b>DataReel:</b> fcrypt is built with the bundled DataReel C++ library 6.4.1, which supplies its strings,
memory buffers, lists, file and folder functions and the file cache used for the older formats. All
cryptography is done by OpenSSL.</li>
</ul>

<h2 id="limits">12. Limits, stated plainly</h2>
<ul>
<li>A file that opens with a password is only as strong as that password: anyone with a copy can guess
offline at the speed PBKDF2 allows. <code>--iter</code> can lower the count to 1,000. Use long random passwords,
128-byte random key files, or RSA keys and smart cards.</li>
<li>The header is not encrypted. Anyone can read the iteration count, the file ID, the number of key slots and
the user names in the RSA and smart card slots. The number of records shows the file's approximate size.</li>
<li>Every credential recovers the same file key. Anyone who can open a file can also add users to it, and a
removed user who kept the file key can still read the file until it is rekeyed. Backups made before a rekey
open with the old credentials.</li>
<li>With <code>--stdout</code>, records are written as they pass their checks, so a file that was cut short or
changed part way through gives some output before the error. Scripts must check the exit code.</li>
<li>The checks of private files, key files and secret files (owner, mode, no symbolic links) are made on
Linux. On Windows, files get the permissions of the folder they are in.</li>
<li>Adding an RSA or smart card user rewrites the key slot area in place, without a temp file, backup or lock.
Keep a copy of an important file before adding users.</li>
<li>Removing whole entries from the end of the access log, and entries after the last tagged one, cannot be
detected.</li>
<li>While a file is being encrypted or decrypted, its keys are in the program's memory.</li>
<li>Older formats are weaker than 2026102, and fdecrypt reads them outside FIPS mode without a switch.
Convert them with fmigrate.</li>
</ul>

<h2 id="quantum">13. Quantum computing</h2>
<ul>
<li><b>Quantum-resistant today:</b> AES-256 record encryption (the best known quantum attack roughly halves its
strength, which leaves about 128 bits), HMAC-SHA256, PBKDF2, AES Key Wrap and the key derivation. A file opened
only with a password or a key file uses no public-key cryptography.</li>
<li><b>Not quantum-resistant:</b> the RSA-OAEP slots of RSA and smart card users. A quantum computer that can
break RSA could recover the file key from any of those slots, so a copy of a file taken today could be
attacked once such a computer exists. For the most sensitive files, rely on long random passwords or key
files.</li>
<li><b>The plan:</b> the next release (2026.110) is required to add quantum-resistant user access: hybrid key
slots that wrap the file key with both RSA-OAEP and ML-KEM-1024 (NIST FIPS 203, available in OpenSSL 3.5), so
an attacker must break both. Files keep the 2026102 format: they still open with a password or key file in
2026.102 and later, and RSA and smart card users can be moved to hybrid slots with <code>--rekey</code>. This
follows the NSA CNSA 2.0 and NIST guidance to move from RSA to ML-KEM with AES-256.</li>
<li><b>Smart cards:</b> today&apos;s CAC and PIV cards hold RSA and elliptic-curve keys only. Until post-quantum
cards are issued, a smart card user can be protected by a hybrid slot that also needs an ML-KEM key file.</li>
</ul>

<h2 id="report">14. Reporting a security issue</h2>
<p>Report security issues privately through the <a href="/contact.php">contact page</a>, not in public issue
trackers. Fixes go into the next release; the <a href="/fcrypt/index.php">README</a> lists every release and
what changed.</p>

</article>
<?php include $_SERVER['DOCUMENT_ROOT'] . '/php/dr2_all_pages_footer.php'; ?>
