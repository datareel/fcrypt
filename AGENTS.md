# fcrypt File Encryption Utility: AI-assisted install, build, upgrade and support

This file is for AI-assisted work on fcrypt, the DataReel file encryption
utility (`fcrypt`, `fdecrypt` and `fmigrate`): it tells an AI agent
(Gemini CLI, Claude Code, GitHub Copilot, Codex and others) how to assist
a site's own administrators and developers to install fcrypt, build it
from source, upgrade older releases to the current release, 2026.109,
maintain a fork, and troubleshoot (2026.110, next: quantum-resistant
hybrid users and OpenSSL 3.5 LTS on every build). The agent assists; it does not replace
the administrators or DataReel support, and it never acts autonomously
(section 0). The people review and approve every step, and problems the
agent cannot solve go to DataReel (section 8.4). `GEMINI.md` and
`CLAUDE.md` in this folder only import this file.

The full documentation is `README.txt` (release notes, key management,
the access log, automation, FIPS mode, smart cards, building) and the
`--help` output of each program. The security design is described at
https://datareel.com/fcrypt/security_design.php. This file points to them
instead of repeating them. When this file and the README or the code
disagree, the README and the code win: say so to the person you work for.

## Before you use AI assistance

**Review all of your agency's or company's AI usage policies, and get formal
written approval from your management team, in the form of a business use
case and justification, before you use any AI assistance with fcrypt.** AI
desktops and command line tools may be used with this guide only in strict
compliance with those policies and that approval.

- **Use only approved enterprise AI models.** An AI agent working with
  fcrypt may process potentially sensitive data: host names, user names,
  file names and paths, command output and logs. Use only your agency's or
  company's enterprise AI models that have built-in safeguards against
  disclosing information and that guarantee your internal information will
  not be used to train public models.
- **Warning: public or free AI tools, open source AI models and self-built
  AI models** may expose your information to public learning models or to
  other parties, depending on how the model is hosted, configured and
  licensed. Use them only after a comprehensive review of what information
  might be exposed and what the potential risks are.
- The entire risk of AI-assisted use rests with the user. DataReel cannot
  be held accountable for actions taken, commands run or other outcomes of
  AI assistance (see https://datareel.com/terms.php).
- **No endorsement.** Any mention of a specific AI tool, model or product
  in this guide, such as Gemini, Gemini CLI, Claude Code or GitHub Copilot,
  is a reference only. It is not an endorsement or a recommendation to use
  that product. Product names are trademarks of their respective owners.

**For the agent:** at the start of a session, ask the person to confirm
that this AI-assisted use is approved under their organization's AI usage
policy and that you are an approved enterprise AI model. If they cannot
confirm it, stop and do not ask for or read any data from their systems.

## 0. Human in the loop: the agent never acts on its own

AI-assisted means the agent assists a person; it never acts
autonomously. Every change to a system or an encrypted file is made by a
person or explicitly approved by one, one step at a time.

- **Advisory mode is the default.** The agent explains the next step and
  prints the exact command and the computer it is for. The person runs it
  and pastes back only output that holds no secret (rule 1). Use this mode
  unless the organization allows the agent to run tools.
- **If tool execution is allowed,** each command still needs its own
  explicit approval before it runs. Never use auto-approve modes: no
  Gemini CLI `--yolo` or auto-accept, no Claude Code permission bypass
  (`--dangerously-skip-permissions`, bypass mode), no auto-run in other
  agents. Commands that decrypt a file or use a credential are run by the
  person, never by the agent (rule 1).
- **No unattended work:** no scheduled, background, batch or scripted
  runs of changing commands, and no loops over files or computers that the
  person has not approved as one listed step.
- **Read-only checks first** (section 8.1); they are shown and approved
  the same way.

**Works with strict AI policies.** These files contain no code that runs
by itself: `AGENTS.md`, `GEMINI.md` and `CLAUDE.md` are text. Everything in
this guide works in advisory mode, with no tool execution by the agent.

## 1. Rules for agents (read these first)

fcrypt protects an organization's files. A wrong step can lose the only
copy of a file's key or expose its contents. Follow these rules on every
task:

1. **Never see a secret or a plaintext.** Never ask for, read, store or
   repeat a password, key file, RSA private key or passphrase, smart card
   PIN, or the contents of a decrypted file. Do not read `.enc` files,
   key files, PIN or password files, rekey input files, or the decrypted
   output. Commands that decrypt (`fdecrypt`, `fdecrypt --stdout`,
   `fmigrate`) are run by the person, and their output is never pasted
   back. Ask for the exit code and the error text only.
2. **Show, then the person runs or approves it.** Before any command that
   changes a computer or an encrypted file (`fcrypt` on a file,
   `fcrypt -r` (removes the source), `fdecrypt -r`, `-o` (overwrite),
   `--add-rsa-key`, `--add-smartcard-cert`, `--add-smartcard-cert-file`,
   `--remove-user`, `--rekey`, `fmigrate` in place), print the command
   and the computer. In advisory mode the person runs it; otherwise wait
   for an explicit yes for that one command (section 0).
3. **Back up before changing.** Before any change to an encrypted file,
   the person copies it to a dated backup folder only they can read.
   An ML-KEM key file (`--generate-pq-key`) is a private key like an RSA
   key: never read it, and make sure the person keeps a backup, because a
   hybrid user cannot open the file without it.
   `--remove-user` and `--rekey` also keep a
   `name.backup-YYYYMMDD-HHMMSS.enc` copy: never delete it. Never delete an
   encrypted file, a backup, a key file or a `.lock` file; move aside only
   with the person's OK. Never suggest `-r` (remove the source file) until
   the person has decrypted the new file once and checked it.
4. **Use `--dry-run` first** for `--remove-user` and `--rekey`: the new
   file is written and checked, then removed, and the file is not changed.
   Use `fmigrate --check` before converting, and `--outdir` to keep the old
   files while the new ones are checked.
5. **Stop on any failed check.** If a check fails or the output is not what
   this guide or the README says to expect, stop and report. Do not
   improvise a fix on a file whose plaintext the person cannot recreate.
6. **Never weaken a safeguard.** Do not suggest `--no-fips` on a system
   that must run in FIPS mode (except for `fmigrate` reading old files,
   section 5.1), `--allow-unencrypted`, a lower `--iter` or `--new-iter`,
   `--smartcard-allow-final-try` or `--smartcard-allow-pin-count-low`, and
   do not loosen file modes (600 key, password and PIN files) to make
   something work. Report instead.
7. **Smart cards: never guess or retry a PIN.** A wrong PIN uses up a try,
   and a locked card (a DoD CAC) needs the card office. List cards with
   `fcrypt --smartcard-list`, `smartcard_list.sh` or `smartcard_list.bat`,
   which never ask for a PIN. Test with a SoftHSM2 software token, never
   with a person's real card.
8. **Passwords and PINs never on the command line.** Use
   `--password-file`, `--password-fd`, `--rsa-key-passphrase-file` or
   `-fd`, `--smartcard-pin-file` or `-fd`, or the prompts, with files only
   the user can read (`chmod 600`). Not `--password=`,
   `--rsa-key-passphrase=` or `--smartcard-pin=` values, which other users
   can see, and never `--password=$(command)`.
9. **No secrets or site data in files you write** (passwords, keys, host
   names, user names), unless the person asks for that file on their own
   systems.
10. **Keep a log.** List each command, on which computer, and its result
    (exit code and non-secret output), and give it to the person at the
    end.

## 2. What fcrypt is

`fcrypt` encrypts files, `fdecrypt` decrypts them and `fmigrate` converts
files from releases before 2026.102 to the current file format, 2026102.
Every file has its own random 256-bit file key; the data is encrypted with
AES-256-CBC with an HMAC-SHA256 on every record, and the header (with the
list of users) is authenticated too. The file key is wrapped for each way
in: a password or key file (PBKDF2-HMAC-SHA256, 600000 iterations by
default), RSA or SSH-RSA public keys of other users, and smart cards
(PKCS#11: DoD CAC, PIV, YubiKey). Since 2026.110 an RSA or card user
can be a quantum-resistant hybrid user: the RSA key or card and an
ML-KEM-1024 key file (`--pq-key`) are both needed (README section
QUANTUM-RESISTANT USERS). With `--fips`, `FCRYPT_FIPS=1` or a host in
FIPS mode, only the OpenSSL FIPS provider is used. The design is
at https://datareel.com/fcrypt/security_design.php.

| Item | Linux | Windows |
| --- | --- | --- |
| Programs | `fcrypt`, `fdecrypt`, `fmigrate` (standalone binaries, no installer; the person copies them to a bin folder) | `fcrypt.exe`, `fdecrypt.exe`, `fmigrate.exe` (standalone, need the Visual C++ Redistributable) |
| Encrypted file | `name.enc` (another extension with `--ext`) | same |
| During a key change | `name.enc.lock` (advisory lock), a temp file, then `name.backup-YYYYMMDD-HHMMSS.enc` | same |
| Access log (off unless asked for) | `~/.fcrypt/logs/access.log` (folder mode 700, file mode 600) | `%USERPROFILE%\.fcrypt\logs\access.log` |
| Smart card list | `fcrypt --smartcard-list`, `smartcard_list.sh` (needs OpenSC) | `fcrypt --smartcard-list`, `smartcard_list.bat` |

Read-only commands (they decrypt nothing and need no credential):

```
fcrypt --version                    # release, OpenSSL version, FIPS mode and provider
fdecrypt --check-version file.enc   # v1 (old) or v2 (2026102); exit 5 for v1
fdecrypt --list-users file.enc      # RSA, smart card and hybrid (+ ML-KEM-1024) users
fdecrypt -l file.enc                # the stored file name
fmigrate --check *.enc              # which files are old format
fcrypt --smartcard-list             # cards, slots, cert IDs and PIN status, no login and no PIN
```

Exit codes: 0 ok, 1 usage or other error, 2 the credential did not open
the file, 3 file or user not found, 4 locked by another writer
(`--remove-user`, `--rekey`), 5 `--check-version` found a v1 file, 7 read
or write error, or not an encrypted file.

## 3. Repository layout and building (development work)

| Path | Contents |
| --- | --- |
| `console/` | `fcrypt.cpp`, `fdecrypt.cpp`, `fmigrate.cpp`; `console/linux` (makefiles and the test scripts), `console/msvc` (nmake), `console/scripts` (`smartcard_list.sh` and helper scripts) |
| `src/`, `include/` | the shared code: the file format (`cryptdb`), AES and key wrapping (`aesdb`), FIPS mode (`fcfips`), key management and the access log (`fckeymgmt`), RSA (`rsadb`), smart cards (`smart_card`) |
| `3plibs/datareel` | the bundled DataReel C++ library 6.4.1; the build compiles these sources directly |
| `aesdb_examples/`, `openssl_examples/` | example programs used to develop the utilities |
| `README*.txt` | release notes, Windows OpenSSL and Visual Studio setup |

Build on RHEL 10: `cd console/linux && make` (needs gcc-c++, make and
openssl-devel; RHEL 8 and 9 use `make -f makefile_rhel8` or
`makefile_rhel9`, and `make clean` when you switch). Linux builds use the
operating system's OpenSSL 3.5 (RHEL 9 and 10). RHEL 8 has two builds:
`makefile_rhel8_openssl35` (OpenSSL 3.5 built in, `build_openssl35.sh`)
and `makefile_rhel8` (the FIPS-validated system OpenSSL 1.1.1 for FIPS
mode hosts); see the README. Other builds stop with an error for an
OpenSSL older than 3.5. Windows: Visual Studio 2022 or 2026 and only
an OpenSSL 3.5.x LTS release (the build stops for any other version);
in `console\msvc` run `msvc.bat` (64-bit, the default) or
`msvc32_vs2026.bat` (32-bit, legacy), then `nmake` (see `README.txt`,
`README_windows_openssl.txt`, `README_windows_setup.txt`).

Build in a copy of the source, not in the clone you commit from, and stage
files by name: never commit binaries or `.o` files.

Tests (Linux, after the build, in `console/linux`): `run_build_tests.sh`,
`run_keymgmt_tests.sh`, `run_security_tests.sh [old_build [2026.101_build]]`,
`run_compat_tests.sh <old_build>`, `run_migrate_tests.sh <old_build> ...`,
`run_smartcard_list_tests.sh`, `run_smartcard_tests.sh` (only with a
SoftHSM2 token, rule 7) and, from 2026.110, `run_pq_tests.sh
[old_build ...]` for the hybrid users. They make their own test files and keys under
`~/tmp` and never use any other file. `FCRYPT_FIPS=1` runs them in FIPS
mode.

Every release bumps `version.txt`, `PROGRAM_VERSION_NUMBER` in
`include/globals.h`, `release_date` in `src/c_config.cpp`, and adds a
release section to `README.txt`.

## 4. New install

1. Download the package and its `.sha256sum` file from
   https://datareel.com/downloads/index.php#fcrypt and check it:
   `sha256sum -c <file>.sha256sum` (Windows: `certutil -hashfile <file>
   SHA256` and compare). Stop if it does not match.
2. **RHEL 8, 9, 10:** unpack `fcrypt_<version>_rhel_8_9_10_binaries.tar.gz`
   and run `./install_fcrypt.sh` (a dry run that shows the build it picks
   and checks the sha256 files), then `./install_fcrypt.sh --install` for
   `~/bin`, or with the person's OK `--system` for `/usr/local/bin`. From
   2026.110 it picks the RHEL 8 build by FIPS mode: `rhel8` (Red Hat's
   FIPS-validated system OpenSSL 1.1.1, no hybrid users) on a host in
   FIPS mode, `rhel8_openssl35` (OpenSSL 3.5 built in) otherwise. Do not
   suggest EPEL's openssl3 packages (not Red Hat, no FIPS provider).
3. **Windows 11, Windows Server 2022 and 2025:** unzip
   `fcrypt_<version>_windows_binaries.zip` (64-bit, the default; the
   `windows_32bit` package is for legacy 32-bit Windows) to a program
   folder and add it to the PATH if the person wants. Install the
   Microsoft Visual C++ Redistributable if it is missing.
4. **Smart cards:** install OpenSC (Linux, or Windows without ActivClient);
   on Windows a DoD CAC uses ActivClient by default when it is installed.
   Check the card with `fcrypt --smartcard-list` (no PIN).
5. Check: `fcrypt --version` shows the release, the OpenSSL version and
   the FIPS mode. The person encrypts and decrypts a test file of their
   own; the agent never sees the password or the file (rule 1).

## 5. AI-assisted upgrade to 2026.109

### 5.1 What changes, and what does not

- **File format:** 2026.102 and later write the 2026102 format. 2026.109
  writes the same format as 2026.102 to 2026.108, so those releases and
  2026.109 decrypt each other's files.
- **Old files** (made by 2023.x and 2025.x releases, format v1) still
  decrypt with `fdecrypt` outside FIPS mode, with a warning that names
  `fmigrate`. Releases before 2026.102 cannot decrypt 2026102 files:
  upgrade every computer that reads the files before writing new ones.
- **FIPS mode:** old format files need algorithms FIPS mode does not
  allow. Convert them with `fmigrate --no-fips` (after a backup, or with
  `--outdir`); the new files then decrypt in FIPS mode.
- **Exit codes (2026.106 and later):** `fdecrypt` exits 2 when the
  credential does not open the file and 3 when the file is missing.
  Scripts that test for exit code 1 should test for non-zero.
- **Kept unchanged:** encrypted files, key files, RSA keys, smart card
  access and the access log.

### 5.2 Steps (one computer at a time, confirm each)

1. **Stop scripts and services** that run fcrypt on this computer.
2. **Back up** the old programs and the encrypted files the person uses
   (rule 3).
3. **Install** the new release (section 4), replacing the old programs.
4. **Check:** `fcrypt --version` says 2026.109; `fdecrypt --check-version`
   for the person's files (exit 0 = v2, exit 5 = v1).
5. **Decrypt a test file once** (the person) and compare it with the
   original; do not paste the contents back.
6. Optional, a separate change with its own OK: `fmigrate` for v1 files
   (`fmigrate --check` first, then with `--outdir` or after a backup).

Roll back: copy the previous programs back. Files written by 2026.109
decrypt with 2026.102 and later; v1 files converted by `fmigrate` do not
decrypt with releases before 2026.102, so keep the old copies until every
computer is upgraded.

## 6. Scripts and services (automation)

README section "AUTOMATION AND PRODUCTION USE".

- Decrypt to a pipe: `fdecrypt --password-file=pw.txt --non-interactive
  --stdout data.enc | consumer`. The data goes to stdout; the script must
  not write it to a log.
- The password file is mode 600 and owned by the service account; with an
  RSA key use `--rsa-key=key.pem --rsa-key-username=name
  --rsa-key-passphrase-file=pp`, with a smart card `--smartcard-pin-file`.
- Secrets from a vault or key service go straight into an `-fd` option
  (for example `--password-fd=0` from a pipe), never through argv.
- Use `--non-interactive` (or `--batch`), `--quiet`, check the exit code
  (section 2), and `--lock-timeout=seconds` for `--remove-user` and
  `--rekey` when another writer may be changing the same file (exit 4).
- `--json` gives machine-readable output for `fdecrypt --check-version` and
  `--list-users`.
- Optional audit trail: `--access-log` on `fdecrypt`, `--remove-user` and
  `--rekey`, checked with `fdecrypt --verify-access-log` (needs the file
  credential, so the person runs it).

## 7. Forks and contributions

fcrypt is free software under the GNU Lesser General Public License (see
`LICENSE`); the bundled DataReel library has its own license files.

- Keep the license and copyright notices, and make the changed source
  available under the same license when you distribute a fork.
- Use your own product name and version numbers, so a fork is never taken
  for a DataReel release.
- Do not change the file format or the meaning of existing bytes: files
  must keep decrypting with fcrypt, and releases 2026.102 and later must
  keep decrypting files from the fork. Run the test scripts (section 3),
  including `run_compat_tests.sh` and `run_security_tests.sh` with old
  builds, before and after a change.
- Security issues: report them privately through
  https://datareel.com/contact.php, not in public issue trackers.

## 8. AI-assisted troubleshooting and support

Diagnose read-only first; change nothing until the person agrees on the
cause and the fix (rule 2).

### 8.1 Where to look

| What | Command or file |
| --- | --- |
| Program version, OpenSSL, FIPS mode | `fcrypt --version` |
| File format | `fdecrypt --check-version file.enc` (`--json` for scripts) |
| Users with RSA or smart card access | `fdecrypt --list-users file.enc` |
| Stored file name | `fdecrypt -l file.enc` |
| Old files in a folder | `fmigrate --check -R folder` |
| Smart cards, slots, cert IDs, PIN tries | `fcrypt --smartcard-list` (no PIN), `smartcard_list.sh` / `smartcard_list.bat` |
| Key change in progress or interrupted | `name.enc.lock` and `name.backup-*.enc` files next to the file |
| Access log | `fdecrypt --verify-access-log file.enc` (the person runs it; entries name users and files) |
| Missing libraries (Linux) | `ldd $(command -v fcrypt) \| grep 'not found'` |

### 8.2 Common problems

- **Exit 2, the credential did not open the file.** The person checks the
  password file (first line only, no extra spaces), the key file, or for
  RSA the user name (`--rsa-key-username`, see `--list-users`) and the
  passphrase. Stop after one failure with a smart card (rule 7).
- **A key, password or PIN file is refused.** fcrypt refuses `--key`,
  private `--rsa-key`, password and PIN files that other users can read.
  The error names the file. The person fixes the mode (`chmod 600`); never suggest
  copying the secret somewhere else.
- **An old file is refused in FIPS mode.** Expected: old formats need
  `--no-fips`, or convert them with `fmigrate --no-fips` (5.1).
- **A traditional PEM RSA key with a passphrase is refused in FIPS mode.**
  The key must be in PKCS#8 format: the person converts their own key
  with the `openssl pkcs8 -topk8` command in the README (FIPS section) and
  sets it to mode 600.
- **Exit 4, locked by another writer.** Another `--remove-user` or
  `--rekey` is changing the file. Wait, or use `--lock-timeout`. Do not
  delete the `.lock` file.
- **The integrity check failed.** The file was changed, cut short or
  damaged, or copied while it was being written. fdecrypt keeps no output.
  Stop (section 8.3).
- **Smart card: card not found, wrong cert ID, or two cards.** Run
  `fcrypt --smartcard-list`; pick the slot with `--smartcard-slot` and the
  cert with `--smartcard-cert-id` (CAC Key Management is ID 03,
  `--smartcard-match=cert.pem` finds a cert). Never send the PIN again
  after a failure (rule 7).
- **Windows: the program does not start.** Install the Visual C++
  Redistributable; use the 32-bit package only on 32-bit Windows.

### 8.3 Stop and escalate at once

Do not try to fix these yourself. Report to the person straight away, with
the summary in 8.4:

- An integrity check failure on a file whose plaintext cannot be recreated.
- A file whose only key slot belongs to a user who has left, a lost key
  file, or a lost RSA private key: only the person's own backups or another
  user's access can help; never try to recover a key.
- A locked or nearly locked smart card PIN.
- A `--verify-access-log` failure: entries were changed, removed or
  reordered.
- Anything that needs a password, key or PIN to be shared, or a safeguard
  to be turned off (rule 6).

### 8.4 Support summary

When a problem is not solved, give the person a summary they can send to
their team or to DataReel (https://datareel.com/contact.php). AI-assisted
support ends here: the people take it from this summary.

1. fcrypt version (`fcrypt --version`, with the OpenSSL version and FIPS
   mode) and OS, and how the release was installed (package or source
   build).
2. `fdecrypt --check-version` and `--list-users` output for the file.
3. The exact error text and exit code, and the access method used
   (password, key file, RSA, smart card), never the credential itself.
4. For smart cards: the `fcrypt --smartcard-list` output and the
   middleware (OpenSC or ActivClient).
5. What happened, when, what changed before it, and every command already
   tried with its result.

Never include passwords, keys, PINs, encrypted or decrypted files, or
their contents in the summary. Remove host, user and file names when the
person asks.

fcrypt is free software, provided as is. Check every command an agent
proposes before it runs; the person who runs it is responsible for the
changes made.

## 9. Report back

End every task with: the computers and files touched (names only), each
command and its result (exit code and non-secret output), the backups made
and where, every warning and what was decided, and the final
`fcrypt --version` and `fdecrypt --check-version` results.
