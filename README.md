# sshole (CVE-2026-123158)

OpenSSH password authentication bypass on musl-based Linux (Alpine, OpenWrt, Buildroot, Yocto).

An `sshd` built against musl libc without PAM will accept any password between 257 and 1024 bytes for an account whose `/etc/shadow` field is a bare `*`. That `*` is the usual marker for key-only users, directory-service users, and `root` on Alpine. On Alpine's official cloud images the default `alpine` user is one of these accounts and has passwordless `doas`, so the bypass reaches root.

This repo has a Docker lab and a proof of concept. Use it on hosts you own or are authorized to test.

* CVE: CVE-2026-123158 (CVSS 8.1)
* Fixed in: OpenSSH 10.6p2, and Alpine packages for 3.16 through edge
* Present since: July 2016
* Not affected: glibc (Debian, Ubuntu, Fedora, RHEL), anything using PAM, Dropbear, OpenBSD

## Files

* `Dockerfile` builds an Alpine image with OpenSSH compiled from source without PAM. `OPENSSH_VER=10.6p1` (default) is vulnerable, `10.6p2` is patched.
* `exploit.py` is a paramiko PoC. It sends a long password a few times on one connection and runs `id` if it gets in.

## How it works

Four unrelated decisions line up to produce the bug.

1. BSD (1980) puts `*` in the password field of accounts that should never log in. A `*` is not a valid hash, so nothing matches it.
2. musl (2012, commit `b3c4cc12`) makes `crypt()` return the string `"*"` on failure instead of `NULL`, so callers that forget to check for `NULL` don't crash. The failure value is now the same string as the "no password" marker.
3. musl (2012, commit `88bf5a8a`) adds SHA-256/512 crypt with a 256-byte key cap for DoS protection. A password over 256 bytes makes `crypt()` fail, which means it returns `"*"`.
4. OpenSSH (2016, the CVE-2016-6210 fix) closes a user-enumeration timing leak. When the stored field is too short to be a salt, `sshd` borrows another account's `$6$` salt and hashes the candidate anyway to keep timing constant. This sends `*` accounts through a real SHA-512 setting, straight into musl's capped path.

Later Alpine (2022) switched `root` from `!` to `*` so keys keep working without PAM, which pulled root into the exposed set.

So for a `*` account, `sshd` hashes the attacker's 300-byte password with a borrowed `$6$` salt. musl rejects the over-long key and hands back `"*"`. `sshd` then compares the `crypt()` result against the stored field with `strcmp()`, gets `"*" == "*"`, and lets them in.

glibc is safe because libxcrypt has no key cap and returns `"*0"` on failure, which never equals `"*"`. PAM is safe because `pam_unix` never calls `crypt()` for a `*` field.

## The vulnerable code

`sys_auth_passwd()` in `auth-passwd.c`, OpenSSH 10.6p1, non-PAM build:

```c
char *pw_password = authctxt->valid ? shadow_pw(pw) : pw->pw_passwd;   /* "*" for a locked account */
...
if (strcmp(pw_password, "") == 0 && strcmp(password, "") == 0)
    return (1);
if (authctxt->valid && pw_password[0] && pw_password[1])               /* "*" is 1 char, so false  */
    salt = pw_password;                                                /* salt stays NULL          */
encrypted_password = xcrypt(password, salt);                           /* crypt(pw, borrowed $6$)  */
return encrypted_password != NULL &&
    strcmp(encrypted_password, pw_password) == 0;                      /* strcmp("*", "*") == 0     */
```

With a NULL salt, `xcrypt()` calls `pick_salt()` in `openbsd-compat/xcrypt.c`, which scans the accounts, copies the first `$`-style hash's salt prefix (`"$6$...$"`), and passes it to musl's `crypt()`. The SHA-512 path returns `"*"` for a 257+ byte key.

### It needs two attempts on one connection

`shadow_pw()` returns `spw->sp_pwdp`, a pointer into the static buffer that `getspnam()` owns:

```c
char *shadow_pw(struct passwd *pw) {
    char *pw_password = pw->pw_passwd;
    struct spwd *spw = getspnam(pw->pw_name);
    if (spw != NULL)
        pw_password = spw->sp_pwdp;   /* points into a static buffer */
    return pw_password;
}
```

`sys_auth_passwd` keeps that pointer across the `xcrypt()` call, and `pick_salt()` calls `getspnam()` again for other accounts (plus an `explicit_bzero()` on the donor). The first attempt in a connection therefore overwrites the buffer `pw_password` aliases, so it no longer reads `*`, and the login is denied. But that same call caches the salt in a `static char salt[32]`.

On the second attempt in the same connection, `pw_password` is reloaded as `*`, and `pick_salt()` returns its cache without touching `getspnam()`. Nothing clobbers the buffer, `strcmp("*", "*")` holds, and the login succeeds. One attempt per connection (plain `sshpass`) never gets there, which is why the PoC retries on one transport.

## The fix

10.6p2 adds a minimum length for the stored hash:

```diff
+#define MIN_PASSWORD_HASH_LEN	4
 #define MAX_PASSWORD_LEN	1024
...
-	return encrypted_password != NULL &&
+	ret = encrypted_password != NULL &&
+	    strlen(pw_password) >= MIN_PASSWORD_HASH_LEN &&
 	    strcmp(encrypted_password, pw_password) == 0;
```

A field shorter than four characters can't match anything after this. OpenSSH treats the root cause as external (musl's `"*"` return), so it's a workaround rather than a real fix. Any other non-PAM program that compares `crypt()` output to a stored `*` with `strcmp()` has the same problem.

## Running the lab

Needs Docker.

```sh
docker build -t sshole:vuln .
docker build -t sshole:fixed --build-arg OPENSSH_VER=10.6p2 .

docker network create sshlab
docker run -d --name target  --network sshlab sshole:vuln
docker run -d --name control --network sshlab sshole:fixed
```

The image creates `alice` with a `*` field (the target), `bob` with a `$6$` hash (the salt donor), and `root` as `*`.

Run the PoC from a client on the same network:

```sh
cat exploit.py | docker run -i --rm --network sshlab sshole:vuln \
  sh -c 'apk add -q python3 py3-paramiko; python3 - target alice'

cat exploit.py | docker run -i --rm --network sshlab sshole:vuln \
  sh -c 'apk add -q python3 py3-paramiko; python3 - target root'

cat exploit.py | docker run -i --rm --network sshlab sshole:vuln \
  sh -c 'apk add -q python3 py3-paramiko; python3 - control alice'
```

Against the vulnerable target:

```
[-] attempt 1: denied
[+] attempt 2: in as root
uid=0(root) gid=0(root) groups=0(root),...
```

`docker logs target` shows `Accepted password for alice` and `Accepted password for root`. The control shows only `Failed password`.

Clean up:

```sh
docker rm -f target control && docker network rm sshlab
docker rmi sshole:vuln sshole:fixed
```

## Checking a real host

You're exposed if all of these hold:

* `sshd` is linked against musl (Alpine, OpenWrt, Buildroot, Yocto)
* it was built without PAM, or runs with `UsePAM no`
* `PasswordAuthentication yes` (the default)
* the version is 10.6p1 or older, or the Alpine package predates the fix for its branch
* some account has `*` in its shadow field and a valid login shell
* some other account has a `$5$` or `$6$` hash

## Fixing it

Update and restart the daemon. `apk` on its own won't restart it:

```sh
apk upgrade -U -a && rc-service sshd restart
```

If you can't update yet, turn off password auth. Confirm key login works first and keep your session open.

Watch out for two traps that make this silently do nothing. sshd uses the first value it finds for a keyword, so an appended `PasswordAuthentication no` is ignored if an uncommented `PasswordAuthentication yes` already appears earlier. And a drop-in file under `sshd_config.d/` is only read if the main config has an `Include /etc/ssh/sshd_config.d/*.conf` line. Stock Alpine ships that Include with the default commented out, so a drop-in is enough there:

```sh
echo "PasswordAuthentication no" > /etc/ssh/sshd_config.d/00-no-passwords.conf
```

Otherwise edit the live line in the main config:

```sh
sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
```

Either way, confirm the effective value before and after restarting:

```sh
sshd -t && sshd -T | grep -i passwordauthentication   # must print: passwordauthentication no
rc-service sshd restart
```

Container images that install `openssh-server` need to be rebuilt, not just restarted.

Look for logins to accounts that have no password:

```sh
grep 'Accepted password for' /var/log/messages | \
  grep -E "for ($(awk -F: '$2=="*"{printf "%s|",$1}' /etc/shadow)root) "
```

Check for new users, new `authorized_keys`, and `doas` activity too. A match on a `*` account means you should treat the box as compromised.

## References

* https://sshhole.com/
* https://www.openssh.org/releasenotes.html
* https://github.com/openssh/openssh-portable/blob/V_10_6_P1/auth-passwd.c
* https://github.com/openssh/openssh-portable/blob/V_10_6_P1/openbsd-compat/xcrypt.c
* https://git.musl-libc.org/cgit/musl/commit/?id=b3c4cc121f70faea45389fe7ddc1127ed5cbd8bb
* https://git.musl-libc.org/cgit/musl/commit/?id=88bf5a8a8d7d796f63cca8589f4de67aa8345f1a
* https://alpinelinux.org/posts/2026-11-05-openssh-password-authentication-bypass/
* https://www.openwall.com/lists/musl/2026/11/05/4
