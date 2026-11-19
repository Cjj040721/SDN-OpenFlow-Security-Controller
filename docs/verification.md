# Verification Record

## Original Linux Integration Run

The original coursework test record contains evidence from a Python 3.9 Ryu environment with Mininet and Open vSwitch.

Verified scenarios:

1. **Topology and DPIDs:** three switches appeared with the expected IDs and six hosts.
2. **L4 learning:** an HTTP request succeeded and installed TCP-specific flows on `s1` and `s3`.
3. **Firewall:** UDP/443, TCP/80, ICMP echo-request, and destination-IP deny rules matched traffic and incremented counters.
4. **Flow statistics:** the controller periodically logged packet and byte counts from all three datapaths.
5. **SYN-flood defence:** a burst of 25 SYN attempts installed a priority-300 drop rule with a 60-second hard timeout; the rule disappeared after expiry.

The original logs are intentionally not redistributed because they contain course-specific absolute paths and verbose runtime output.

## Cleaned Candidate Checks

The cleaned candidate is checked with:

```bash
python -m py_compile controller.py topo.py
python -m json.tool rules.json > /dev/null
```

Additional configuration assertions cover:

- Exactly four firewall rules on datapath `0000000000000002`.
- DPIDs `1`, `2`, and `3` assigned to `s1`, `s2`, and `s3`.
- Six hosts in the `10.0.0.0/24` network.
- SYN threshold `20`, detection window `10` seconds, and ban duration `60` seconds.

## Current Environment Limitation

Ryu and Mininet are not installed in the current macOS environment, and Mininet requires Linux networking features. The integration run has therefore **not** been repeated for this cleaned candidate. No dynamic success is claimed beyond the preserved original run and the static checks listed above.
