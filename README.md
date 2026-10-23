# php2shell-eth (Etragardh)

Profile-driven reproducer for the PHP multipart/session chain studied in this
repository.  It recovers request-heap and `libphp.so` bases from the target's
HTTP response and then passes a caller-supplied command to the final B2 stage.

Use it only against systems you own or are explicitly authorized to test.

## Requirements

- Python 3.10 or newer on the machine running the PoC;
- no third-party Python packages (standard library only);
- direct TCP access to the target HTTP port;
- Apache `mpm_prefork`/`apache2handler` matching a bundled profile;
- an exact match for the profile's architecture, PHP build, extensions and
  effective ini configuration.

The included profiles target official `php:8.3.35-apache` image builds:

- `php-8.3.35-arm64-official` — unmodified `php.ini-production`;
- `php-8.3.35-arm64-official-no-ini` — no loaded main `php.ini`.
- `php-8.3.35-amd64-official` — AMD64 with unmodified
  `php.ini-production`.

List or inspect profiles without contacting a target:

```sh
./php2shell-eth.py --list-profiles
./php2shell-eth.py \
  --profile php-8.3.35-arm64-official-no-ini --show-profile
```

## Run

Start with a harmless marker command in an isolated lab:

```sh
./php2shell-eth.py 127.0.0.1 \
  --port 8080 \
  --workers 150 \
  --profile php-8.3.35-arm64-official \
  --cmd 'id >/tmp/php2shell-eth'
```

`--cmd` is UTF-8 encoded and inserted into the forged string consumed by the
target's `system()`.  Quote it for the local shell; shell metacharacters are
interpreted on the target.  NUL bytes and commands that do not fit the
selected profile's B2 carrier are rejected before any request is sent.  The
bundled profiles currently allow at most 191 command bytes.

Useful options:

```text
--path /index.php       request path
--retries 3             A1/B1 attempts
--leak-only             stop after recovering main/libphp bases
--profile NAME          select an exact target contract
--workers N             target request-processing slots; see below
```

A calibrated B2 normally terminates its Apache child, so success is
consistent with an empty HTTP response.  A normal response is reported as
`B2_UNCONFIRMED` (exit 4).  Always verify the requested side effect on a lab
target when possible.

## Chain

1. **A1** drives multipart/session cleanup into an OOM bailout, leaving stale
   process-global session pointers into the destroyed request heap.
2. **B1** places a forged `zend_string` at the stale session-ID address.  The
   resulting `Set-Cookie` discloses enough target memory to recover a
   structural ZendMM main-chunk base and repeated `zval_ptr_dtor` pointers,
   from which the `libphp.so` base is derived.
3. **A2** reaches a second calibrated OOM after publishing a request-allocated
   `zend_reference` through `PS(http_session_vars)`.
4. **B2** reclaims that stale reference and supplies a fake `HashTable` whose
   destructor points to `zif_system`.  The `--cmd` bytes occupy the synthetic
   argument string.

Absolute ASLR addresses are not stored in a profile.  B1 derives them anew
from the target response on every run.

## Profiles

Profiles live in `profiles/`, one module per exact environment.  A profile is
a calibrated contract, not a random seed.  It declares:

- image/build identity and effective ini settings;
- architecture and Zend ABI field offsets;
- ZendMM geometry and leak-validation rules;
- build-relative `libphp.so` symbol offsets;
- request-main-relative stale-object/carrier offsets;
- complete A1, B1, A2 and B2 request geometry and expected statuses.

The command is intentionally not profile data.  It is validated at runtime
and supplied with `--cmd`.

Profile modules are discovered automatically at startup.  To add one, create
a non-private `.py` file in `profiles/` that exposes a `PROFILE` instance with
a unique `PROFILE.name`; no registry import or tuple entry is needed.  Files
whose names begin with `_` are ignored, and `types.py` is reserved for the
shared profile schema.  The current default remains
`php-8.3.35-arm64-official`.

Changing only an ini value can change request allocation order and require a
new profile.  A different architecture, PHP build, SAPI, extension set or
allocator history must not be assumed compatible merely because `php -v`
shows the same version.

In simpler words: A valid profile for the target environment is required for successful exploitation. And you changing as much as a single ini-setting might be enough to skew the calibration.

## Choosing `--workers`

All four stages must reach the same Apache child.  With `--workers N`, the PoC
opens `N-1` incomplete request bodies and leaves one request-processing slot
for the chain.  The holders send 1024-byte heartbeats every 0.75 seconds so
Apache's `mod_reqtimeout` does not discard them during a WAN transfer.

For a dedicated one-worker lab, use:

```text
--workers 1
```

For prefork Apache, `N` must equal the effective `MaxRequestWorkers`, not the
number of child processes visible at one instant.  Too small leaves multiple
uncontrolled workers; too large can occupy every worker or leave requests in
the listen backlog.

On Debian-derived Apache installations, inspect the active configuration:

```sh
apachectl -M 2>&1 | grep mpm
apachectl -t -D DUMP_INCLUDES
grep -RniE '^[[:space:]]*(ServerLimit|MaxRequestWorkers)[[:space:]]' \
  /etc/apache2/mods-enabled /etc/apache2/conf-enabled
```

In Docker, run those commands inside the target container:

```sh
docker exec TARGET apachectl -M
docker exec TARGET sh -c \
  "grep -RniE '^[[:space:]]*(ServerLimit|MaxRequestWorkers)[[:space:]]' \
   /etc/apache2/mods-enabled /etc/apache2/conf-enabled"
```

Use `DUMP_INCLUDES` to resolve override order.  The official image normally
gets prefork's value from `mods-enabled/mpm_prefork.conf`, but mounted or
later `conf-enabled` files can override it.  `server-status?auto` is useful
for observing `BusyWorkers` and `IdleWorkers`, but it may not expose the
configured maximum.

Do not calibrate through unrelated production traffic, a load balancer that
can switch backends, or an unknown autoscaling pool.  Use a dedicated target
instance whenever possible.  If a holder receives a response or disconnects,
the runner stops with `WORKER_PINNING_FAILED` (exit 5) rather than continuing
on an uncontrolled worker.

## Calibrating another profile

Calibration requires a disposable target and a debugger.  The final runner
does not use GDB or `/proc`, but those are appropriate while deriving a new
profile.

1. Pin the exact image digest, architecture, SAPI, extension list,
   `libphp.so` hash and complete effective ini contract.
2. Clone the closest module in `profiles/`, give its `PROFILE` a unique name,
   and keep the target at one worker.  The new module is discovered
   automatically; do not edit `profiles/__init__.py`.
3. Restart the worker before each candidate intended for the profile; warm
   ZendMM cache history can make an accidental geometry look stable.
4. Calibrate A1 and verify its bailout stack, stale `PS(id)`, `PS(mod_data)`,
   cookie state and request-main-relative stale-ID offset.
5. For B1, first obtain a short forged marker cookie.  Then find the minimum
   disclosure that contains a valid chunk header and repeated natural
   `zval_ptr_dtor` values.  Validate addresses only from the HTTP response.
6. Verify A2's OOM in both status and body, then measure the stale
   `PS(http_session_vars)` reference relative to request-main.
7. Run B2 with refcount 2 and pause before multipart END.  Confirm reclaim and
   measure the first fake-array carrier without executing its destructor.
8. Put only relative offsets and request geometry in the profile.  Perform a
   cold end-to-end run, verify the command side effect, and repeat on an
   independent matching target.

The stage CLIs expose calibration overrides:

```sh
python3 a1.py --help
python3 b1.py --help
python3 a2b2.py --help
```

Run the included regression tests after editing the core or a profile:

```sh
python3 -m unittest discover -s tests -v
```

## Exit codes

```text
0  chain completed or --leak-only succeeded
2  no valid B1 leak / CLI usage error from argparse
3  A2 did not match its calibrated outcome
4  B2 returned an HTTP response and is unconfirmed
5  one or more worker pins were lost
```

