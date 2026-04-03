# Vulnerability Comparison Report

## Summary

  SBOM Components (Raw): 11725
  Deduplicated PURLs:    535
  Clean (0 vulns):       402
  Vulnerable:            133

  Scanner      | Pkgs Scanned   | Pkgs w/ Vulns  | Total Vuln IDs
  OSV          | 535            | 51             | 226
  Grype        | 535            | 122            | 141
  All 2 agree: 114    ≥2 agree: 114    Total: 253  (CVE:248 GHSA:4 Other:1)
  Exclusive to: OSV:112  Grype:27

## VULNERABLE PACKAGES — [O]SV [G]rype findings

  ▸ Python (PyPI) (14 packages)
    ✔✔  pkg:pypi/certifi@2019.11.28
    ✔✔  pkg:pypi/cryptography@3.3.2
    ✔✔  pkg:pypi/flask@3.0.2
    ✔✔  pkg:pypi/idna@2.7
    ✔✔  pkg:pypi/idna@2.8
    ✔✔  pkg:pypi/pip@20.0.2
    ✔✘  pkg:pypi/python-apt@2.0.1%2Bubuntu0.20.4.1
    ✔✔  pkg:pypi/requests@2.19.1
    ✔✔  pkg:pypi/requests@2.22.0
    ✔✔  pkg:pypi/setuptools@45.2.0
    ✔✔  pkg:pypi/urllib3@1.23
    ✔✔  pkg:pypi/urllib3@1.25.8
    ✔✔  pkg:pypi/werkzeug@3.0.1
    ✔✔  pkg:pypi/wheel@0.34.2

  ▸ Debian/Ubuntu (deb) (101 packages)
    ✔✔  pkg:deb/ubuntu/binutils@2.34-6ubuntu1.11
    ✘✔  pkg:deb/ubuntu/binutils-common@2.34-6ubuntu1.11
    ✘✔  pkg:deb/ubuntu/binutils-x86-64-linux-gnu@2.34-6ubuntu1.11
    ✔✔  pkg:deb/ubuntu/coreutils@8.30-3ubuntu2
    ✘✔  pkg:deb/ubuntu/cpp-9@9.4.0-1ubuntu1~20.04.2
    ✔✘  pkg:deb/ubuntu/curl@7.68.0-1ubuntu2.25
    ✔✔  pkg:deb/ubuntu/dbus@1.12.16-2ubuntu2.3
    ✘✔  pkg:deb/ubuntu/dbus-user-session@1.12.16-2ubuntu2.3
    ✘✔  pkg:deb/ubuntu/dirmngr@2.2.19-3ubuntu2.5
    ✔✘  pkg:deb/ubuntu/dpkg@1.19.7ubuntu3.2
    ✘✔  pkg:deb/ubuntu/g%2B%2B-9@9.4.0-1ubuntu1~20.04.2
    ✘✔  pkg:deb/ubuntu/gcc-10-base@10.5.0-1ubuntu1~20.04
    ✔✔  pkg:deb/ubuntu/gcc-9@9.4.0-1ubuntu1~20.04.2
    ✘✔  pkg:deb/ubuntu/gcc-9-base@9.4.0-1ubuntu1~20.04.2
    ✘✔  pkg:deb/ubuntu/gir1.2-packagekitglib-1.0@1.1.13-2ubuntu1.1
    ✘✔  pkg:deb/ubuntu/gnupg@2.2.19-3ubuntu2.5
    ✘✔  pkg:deb/ubuntu/gnupg-l10n@2.2.19-3ubuntu2.5
    ✘✔  pkg:deb/ubuntu/gnupg-utils@2.2.19-3ubuntu2.5
    ✘✔  pkg:deb/ubuntu/gpg@2.2.19-3ubuntu2.5
    ✘✔  pkg:deb/ubuntu/gpg-agent@2.2.19-3ubuntu2.5
    ✘✔  pkg:deb/ubuntu/gpg-wks-client@2.2.19-3ubuntu2.5
    ✘✔  pkg:deb/ubuntu/gpg-wks-server@2.2.19-3ubuntu2.5
    ✘✔  pkg:deb/ubuntu/gpgconf@2.2.19-3ubuntu2.5
    ✘✔  pkg:deb/ubuntu/gpgsm@2.2.19-3ubuntu2.5
    ✘✔  pkg:deb/ubuntu/gpgv@2.2.19-3ubuntu2.5
    ✘✔  pkg:deb/ubuntu/libasan5@9.4.0-1ubuntu1~20.04.2
    ✘✔  pkg:deb/ubuntu/libatomic1@10.5.0-1ubuntu1~20.04
    ✘✔  pkg:deb/ubuntu/libbinutils@2.34-6ubuntu1.11
    ✘✔  pkg:deb/ubuntu/libc-bin@2.31-0ubuntu9.17
    ✘✔  pkg:deb/ubuntu/libc-dev-bin@2.31-0ubuntu9.18
    ✘✔  pkg:deb/ubuntu/libc6@2.31-0ubuntu9.18
    ✘✔  pkg:deb/ubuntu/libc6-dev@2.31-0ubuntu9.18
    ✘✔  pkg:deb/ubuntu/libcc1-0@10.5.0-1ubuntu1~20.04
    ✘✔  pkg:deb/ubuntu/libctf-nobfd0@2.34-6ubuntu1.11
    ✘✔  pkg:deb/ubuntu/libctf0@2.34-6ubuntu1.11
    ✘✔  pkg:deb/ubuntu/libdbus-1-3@1.12.16-2ubuntu2.3
    ✘✔  pkg:deb/ubuntu/libelf1@0.176-1.1ubuntu0.1
    ✘✔  pkg:deb/ubuntu/libgcc-9-dev@9.4.0-1ubuntu1~20.04.2
    ✘✔  pkg:deb/ubuntu/libgcc-s1@10.5.0-1ubuntu1~20.04
    ✔✔  pkg:deb/ubuntu/libgcrypt20@1.8.5-5ubuntu1.1
    ✘✔  pkg:deb/ubuntu/libglib2.0-0@2.64.6-1~ubuntu20.04.9
    ✘✔  pkg:deb/ubuntu/libglib2.0-bin@2.64.6-1~ubuntu20.04.9
    ✘✔  pkg:deb/ubuntu/libglib2.0-data@2.64.6-1~ubuntu20.04.9
    ✘✔  pkg:deb/ubuntu/libgomp1@10.5.0-1ubuntu1~20.04
    ✘✔  pkg:deb/ubuntu/libicu66@66.1-2ubuntu2.1
    ✘✔  pkg:deb/ubuntu/libitm1@10.5.0-1ubuntu1~20.04
    ✘✔  pkg:deb/ubuntu/liblsan0@10.5.0-1ubuntu1~20.04
    ✘✔  pkg:deb/ubuntu/libncurses6@6.2-0ubuntu2.1
    ✘✔  pkg:deb/ubuntu/libncursesw6@6.2-0ubuntu2.1
    ✘✔  pkg:deb/ubuntu/libnss-systemd@245.4-4ubuntu3.24
    ✘✔  pkg:deb/ubuntu/libpackagekit-glib2-18@1.1.13-2ubuntu1.1
    ✘✔  pkg:deb/ubuntu/libpam-modules@1.3.1-5ubuntu4.7
    ✘✔  pkg:deb/ubuntu/libpam-modules-bin@1.3.1-5ubuntu4.7
    ✘✔  pkg:deb/ubuntu/libpam-runtime@1.3.1-5ubuntu4.7
    ✘✔  pkg:deb/ubuntu/libpam-systemd@245.4-4ubuntu3.24
    ✘✔  pkg:deb/ubuntu/libpam0g@1.3.1-5ubuntu4.7
    ✘✔  pkg:deb/ubuntu/libpcre2-8-0@10.34-7ubuntu0.1
    ✘✔  pkg:deb/ubuntu/libpcre3@2%3A8.39-12ubuntu0.1
    ✘✔  pkg:deb/ubuntu/libperl5.30@5.30.0-9ubuntu0.5
    ✘✔  pkg:deb/ubuntu/libpolkit-agent-1-0@0.105-26ubuntu1.3
    ✘✔  pkg:deb/ubuntu/libpolkit-gobject-1-0@0.105-26ubuntu1.3
    ✘✔  pkg:deb/ubuntu/libpython3.8@3.8.10-0ubuntu1~20.04.18
    ✘✔  pkg:deb/ubuntu/libpython3.8-dev@3.8.10-0ubuntu1~20.04.18
    ✘✔  pkg:deb/ubuntu/libpython3.8-minimal@3.8.10-0ubuntu1~20.04.18
    ✘✔  pkg:deb/ubuntu/libpython3.8-stdlib@3.8.10-0ubuntu1~20.04.18
    ✘✔  pkg:deb/ubuntu/libquadmath0@10.5.0-1ubuntu1~20.04
    ✘✔  pkg:deb/ubuntu/libsoup2.4-1@2.70.0-1ubuntu0.5
    ✘✔  pkg:deb/ubuntu/libstdc%2B%2B-9-dev@9.4.0-1ubuntu1~20.04.2
    ✘✔  pkg:deb/ubuntu/libstdc%2B%2B6@10.5.0-1ubuntu1~20.04
    ✘✔  pkg:deb/ubuntu/libsystemd0@245.4-4ubuntu3.24
    ✔✔  pkg:deb/ubuntu/libtasn1-6@4.16.0-2ubuntu0.1
    ✘✔  pkg:deb/ubuntu/libtinfo6@6.2-0ubuntu2.1
    ✘✔  pkg:deb/ubuntu/libtsan0@10.5.0-1ubuntu1~20.04
    ✘✔  pkg:deb/ubuntu/libubsan1@10.5.0-1ubuntu1~20.04
    ✘✔  pkg:deb/ubuntu/libudev1@245.4-4ubuntu3.24
    ✔✘  pkg:deb/ubuntu/libxml2@2.9.10%2Bdfsg-5ubuntu0.20.04.10
    ✘✔  pkg:deb/ubuntu/login@1%3A4.8.1-1ubuntu5.20.04.5
    ✘✔  pkg:deb/ubuntu/ncurses-base@6.2-0ubuntu2.1
    ✘✔  pkg:deb/ubuntu/ncurses-bin@6.2-0ubuntu2.1
    ✔✘  pkg:deb/ubuntu/openssl@1.1.1f-1ubuntu2.24
    ✔✔  pkg:deb/ubuntu/packagekit@1.1.13-2ubuntu1.1
    ✘✔  pkg:deb/ubuntu/packagekit-tools@1.1.13-2ubuntu1.1
    ✘✔  pkg:deb/ubuntu/passwd@1%3A4.8.1-1ubuntu5.20.04.5
    ✔✔  pkg:deb/ubuntu/patch@2.7.6-6
    ✔✔  pkg:deb/ubuntu/perl@5.30.0-9ubuntu0.5
    ✘✔  pkg:deb/ubuntu/perl-base@5.30.0-9ubuntu0.5
    ✘✔  pkg:deb/ubuntu/perl-modules-5.30@5.30.0-9ubuntu0.5
    ✔✔  pkg:deb/ubuntu/policykit-1@0.105-26ubuntu1.3
    ✘✔  pkg:deb/ubuntu/python-apt-common@2.0.1ubuntu0.20.04.1
    ✘✔  pkg:deb/ubuntu/python-pip-whl@20.0.2-5ubuntu1.11
    ✘✔  pkg:deb/ubuntu/python3-apt@2.0.1ubuntu0.20.04.1
    ✘✔  pkg:deb/ubuntu/python3-pip@20.0.2-5ubuntu1.11
    ✔✔  pkg:deb/ubuntu/python3.8@3.8.10-0ubuntu1~20.04.18
    ✘✔  pkg:deb/ubuntu/python3.8-dev@3.8.10-0ubuntu1~20.04.18
    ✘✔  pkg:deb/ubuntu/python3.8-minimal@3.8.10-0ubuntu1~20.04.18
    ✔✔  pkg:deb/ubuntu/systemd@245.4-4ubuntu3.24
    ✘✔  pkg:deb/ubuntu/systemd-sysv@245.4-4ubuntu3.24
    ✘✔  pkg:deb/ubuntu/systemd-timesyncd@245.4-4ubuntu3.24
    ✔✘  pkg:deb/ubuntu/tar@1.30%2Bdfsg-7ubuntu0.20.04.4
    ✔✘  pkg:deb/ubuntu/util-linux@2.34-0.1ubuntu9.6
    ✔✘  pkg:deb/ubuntu/xz-utils@5.2.4-1ubuntu1.1

  ▸ Go (18 packages)
    ✔✔  pkg:golang/github.com/containerd/containerd/v2@v2.0.4
    ✔✘  pkg:golang/github.com/docker/buildx
    ✔✔  pkg:golang/github.com/docker/cli@v28.0.4%2Bincompatible
    ✔✔  pkg:golang/github.com/docker/cli@v28.1.0%2Bincompatible
    ✔✘  pkg:golang/github.com/docker/compose/v2
    ✔✔  pkg:golang/github.com/docker/docker@v28.0.4%2Bincompatible
    ✔✔  pkg:golang/github.com/docker/docker@v28.1.0%2Bincompatible
    ✔✔  pkg:golang/github.com/go-viper/mapstructure/v2@v2.0.0
    ✔✔  pkg:golang/github.com/moby/buildkit@v0.21.0
    ✔✔  pkg:golang/go.opentelemetry.io/otel/sdk@v1.31.0
    ✔✔  pkg:golang/go.opentelemetry.io/otel/sdk@v1.34.0
    ✔✔  pkg:golang/golang.org/x/crypto@v0.37.0
    ✔✘  pkg:golang/golang.org/x/net@v0.39.0
    ✔✔  pkg:golang/golang.org/x/oauth2@v0.23.0
    ✔✔  pkg:golang/golang.org/x/oauth2@v0.25.0
    ✔✔  pkg:golang/google.golang.org/grpc@v1.69.4
    ✔✔  pkg:golang/google.golang.org/grpc@v1.71.1
    ✔✔  pkg:golang/stdlib@1.23.8

## VULNERABILITY DETAIL — All Scanner Findings

  Shows all vulnerabilities discovered and scanner agreement status.
  O G  Vulnerability          Severity    CVSS  EPSS         KEV   Expl
  ━━ Python (PyPI) ━━
  ┌─ certifi@2019.11.28
  │ ✔✔ CVE-2022-23491         HIGH         7.5   EPSS:0.00051
  │        ↳ O:GHSA-43fp-rhv2-5gv8,PYSEC-2022-42986
  │ ✔✔ CVE-2023-37920         CRITICAL     9.8   EPSS:0.00112
  │        ↳ O:GHSA-xqr8-7jwr-rhp7,PYSEC-2023-135
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ cryptography@3.3.2
  │ ✔✔ CVE-2023-0286          HIGH         7.4   EPSS:0.88474
  │        ↳ O:GHSA-x4qr-2fvf-3mr5
  │ ✔✔ CVE-2023-23931         MEDIUM       6.5   EPSS:0.00804       1
  │        ↳ O:GHSA-w7pp-m8wf-vj6r,PYSEC-2023-11
  │ ✔✔ CVE-2023-49083         HIGH         7.5   EPSS:0.01289       1
  │        ↳ O:GHSA-jfhm-5ghh-2f97,PYSEC-2023-254
  │ ✔✔ CVE-2023-50782         HIGH         7.5   EPSS:0.00252
  │        ↳ O:GHSA-3ww4-gg4f-jr7f
  │ ✔✔ CVE-2024-0727          MEDIUM       5.5   EPSS:0.00236
  │        ↳ O:GHSA-9v9h-cgj8-h64p
  │ ✔✔ CVE-2026-26007         HIGH         8.2   EPSS:0.00009
  │        ↳ O:GHSA-r6ph-v2qm-q3c2
  │ ✔✔ CVE-2026-34073         MEDIUM       6.3   EPSS:0.00023
  │        ↳ O:GHSA-m959-cc7f-wv43
  │ ✔✔ GHSA-5CPQ-8WJ7-HF2V    ?            -                        n/a
  │ ✔✔ GHSA-JM77-QPHF-C4W8    ?            -                        n/a
  │ ✔✔ GHSA-V8GR-M533-GHJ9    ?            -                        n/a
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ flask@3.0.2
  │ ✔✔ CVE-2026-27205         MEDIUM       4.3   EPSS:0.00011
  │        ↳ O:GHSA-68rp-wp8r-4726
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ idna@2.7
  │ ✔✔ CVE-2024-3651          HIGH         7.5   EPSS:0.00670       1
  │        ↳ O:GHSA-jjg7-2v4v-x38h,PYSEC-2024-60
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ idna@2.8
  │ ✔✔ CVE-2024-3651          HIGH         7.5   EPSS:0.00670       1
  │        ↳ O:GHSA-jjg7-2v4v-x38h,PYSEC-2024-60
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ pip@20.0.2
  │ ✔✔ CVE-2021-3572          MEDIUM       5.7   EPSS:0.00240       2
  │        ↳ O:GHSA-5xp3-jfq3-5q8x,PYSEC-2021-437
  │ ✔✔ CVE-2023-5752          MEDIUM       5.5   EPSS:0.00075
  │        ↳ O:GHSA-mq26-g339-26xf,PYSEC-2023-228
  │ ✔✔ CVE-2025-8869          MEDIUM       5.9   EPSS:0.00020
  │        ↳ O:GHSA-4xh5-x5gv-qwph
  │ ✔✔ CVE-2026-1703          LOW          2.0   EPSS:0.00022       1
  │        ↳ O:GHSA-6vgw-5pg2-w6jp
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ python-apt@2.0.1+ubuntu0.20.4.1
  │ ✔✘ CVE-2019-15795         MEDIUM       4.7   EPSS:0.00184
  │        ↳ O:GHSA-rp8m-h266-53jh
  │ ✔✘ CVE-2019-15796         MEDIUM       4.7   EPSS:0.00174
  │        ↳ O:GHSA-pj65-3pf6-c5q4
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ requests@2.19.1
  │ ✔✔ CVE-2018-18074         HIGH         7.5   EPSS:0.00243       3
  │        ↳ O:GHSA-x84v-xcm2-53pg,PYSEC-2018-28
  │ ✔✔ CVE-2023-32681         MEDIUM       6.1   EPSS:0.06278       1
  │        ↳ O:GHSA-j8r2-6x86-q33q,PYSEC-2023-74
  │ ✔✔ CVE-2024-35195         MEDIUM       5.6   EPSS:0.00044
  │        ↳ O:GHSA-9wx4-h78v-vm56
  │ ✔✔ CVE-2024-47081         MEDIUM       5.3   EPSS:0.00070       1
  │        ↳ O:GHSA-9hjg-9r4m-mvj7
  │ ✔✔ CVE-2026-25645         MEDIUM       5.5   EPSS:0.00004
  │        ↳ O:GHSA-gc5v-m9x4-r6x2
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ requests@2.22.0
  │ ✔✔ CVE-2023-32681         MEDIUM       6.1   EPSS:0.06278       1
  │        ↳ O:GHSA-j8r2-6x86-q33q,PYSEC-2023-74
  │ ✔✔ CVE-2024-35195         MEDIUM       5.6   EPSS:0.00044
  │        ↳ O:GHSA-9wx4-h78v-vm56
  │ ✔✔ CVE-2024-47081         MEDIUM       5.3   EPSS:0.00070       1
  │        ↳ O:GHSA-9hjg-9r4m-mvj7
  │ ✔✔ CVE-2026-25645         MEDIUM       5.5   EPSS:0.00004
  │        ↳ O:GHSA-gc5v-m9x4-r6x2
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ setuptools@45.2.0
  │ ✔✔ CVE-2022-40897         MEDIUM       5.9   EPSS:0.00513       1
  │        ↳ O:GHSA-r9hx-vwmv-q579,PYSEC-2022-43012
  │ ✔✔ CVE-2024-6345          HIGH         8.8   EPSS:0.07336
  │        ↳ O:GHSA-cx63-2mw6-8hw5
  │ ✔✔ CVE-2025-47273         HIGH         8.8   EPSS:0.00487       5
  │        ↳ O:GHSA-5rjg-fvgr-3xxf,PYSEC-2025-49
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ urllib3@1.23
  │ ✔✔ CVE-2018-25091         MEDIUM       6.1   EPSS:0.00434
  │        ↳ O:GHSA-gwvm-45gx-3cf8,PYSEC-2023-207
  │ ✔✔ CVE-2019-11236         MEDIUM       6.1   EPSS:0.00624       1
  │        ↳ O:GHSA-r64q-w8jr-g9qp,PYSEC-2019-132
  │ ✔✔ CVE-2019-11324         HIGH         7.5   EPSS:0.01315
  │        ↳ O:GHSA-mh33-7rrq-662w,PYSEC-2019-133
  │ ✔✔ CVE-2020-26137         MEDIUM       6.5   EPSS:0.00903       1
  │        ↳ O:GHSA-wqvq-5m8c-6g24,PYSEC-2020-148
  │ ✔✘ CVE-2021-33503         HIGH         7.5   EPSS:0.00863
  │        ↳ O:PYSEC-2021-108
  │ ✔✔ CVE-2023-43804         HIGH         8.1   EPSS:0.00867
  │        ↳ O:GHSA-v845-jxx5-vc9f,PYSEC-2023-192
  │ ✔✔ CVE-2023-45803         MEDIUM       4.2   EPSS:0.00051
  │        ↳ O:GHSA-g4mx-q9vg-27p4,PYSEC-2023-212
  │ ✔✔ CVE-2024-37891         MEDIUM       6.5   EPSS:0.00263       1
  │        ↳ O:GHSA-34jh-p97f-mpxf
  │ ✔✔ CVE-2025-50181         MEDIUM       6.1   EPSS:0.00026       1
  │        ↳ O:GHSA-pq67-6m6q-mj2v
  │ ✔✔ CVE-2025-66471         HIGH         8.9   EPSS:0.00027
  │        ↳ O:GHSA-2xpw-w6gg-jr37
  │ ✔✔ CVE-2026-21441         HIGH         8.9   EPSS:0.00027
  │        ↳ O:GHSA-38jv-5279-wg99
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ urllib3@1.25.8
  │ ✔✔ CVE-2020-26137         MEDIUM       6.5   EPSS:0.00903       1
  │        ↳ O:GHSA-wqvq-5m8c-6g24,PYSEC-2020-148
  │ ✔✔ CVE-2021-33503         HIGH         7.5   EPSS:0.00863
  │        ↳ O:GHSA-q2q7-5pp4-w6pg,PYSEC-2021-108
  │ ✔✔ CVE-2023-43804         HIGH         8.1   EPSS:0.00867
  │        ↳ O:GHSA-v845-jxx5-vc9f,PYSEC-2023-192
  │ ✔✔ CVE-2023-45803         MEDIUM       4.2   EPSS:0.00051
  │        ↳ O:GHSA-g4mx-q9vg-27p4,PYSEC-2023-212
  │ ✔✔ CVE-2024-37891         MEDIUM       6.5   EPSS:0.00263       1
  │        ↳ O:GHSA-34jh-p97f-mpxf
  │ ✔✔ CVE-2025-50181         MEDIUM       6.1   EPSS:0.00026       1
  │        ↳ O:GHSA-pq67-6m6q-mj2v
  │ ✔✔ CVE-2025-66418         HIGH         8.9   EPSS:0.00029
  │        ↳ O:GHSA-gm62-xv2j-4w53
  │ ✔✔ CVE-2025-66471         HIGH         8.9   EPSS:0.00027
  │        ↳ O:GHSA-2xpw-w6gg-jr37
  │ ✔✔ CVE-2026-21441         HIGH         8.9   EPSS:0.00027
  │        ↳ O:GHSA-38jv-5279-wg99
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ werkzeug@3.0.1
  │ ✔✔ CVE-2024-34069         HIGH         7.5   EPSS:0.38929
  │        ↳ O:GHSA-2g68-c3qc-8985
  │ ✔✔ CVE-2024-49766         MEDIUM       6.3   EPSS:0.01392
  │        ↳ O:GHSA-f9vj-2wh5-fj8j
  │ ✔✔ CVE-2024-49767         HIGH         7.5   EPSS:0.01090
  │        ↳ O:GHSA-q34m-jh98-gwm2
  │ ✔✔ CVE-2025-66221         MEDIUM       6.3   EPSS:0.00032
  │        ↳ O:GHSA-hgf8-39gv-g3f2
  │ ✔✔ CVE-2026-21860         MEDIUM       6.3   EPSS:0.00022
  │        ↳ O:GHSA-87hc-h4r5-73f7
  │ ✔✔ CVE-2026-27199         MEDIUM       6.3   EPSS:0.00020       1
  │        ↳ O:GHSA-29vq-49wr-vm6x
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ wheel@0.34.2
  │ ✔✔ CVE-2022-40898         HIGH         7.5   EPSS:0.00162       1
  │        ↳ O:GHSA-qwmp-2cf2-g9g6,PYSEC-2022-43017
  └────────────────────────────────────────────────────────────────────────────────

  ━━ Debian/Ubuntu (deb) ━━
  ┌─ binutils@2.34-6ubuntu1.11
  │ ✔✔ CVE-2017-13716         HIGH         7.1   EPSS:0.00237
  │        ↳ O:UBUNTU-CVE-2017-13716
  │ ✔✔ CVE-2019-1010204       MEDIUM       5.5   EPSS:0.00143
  │        ↳ O:UBUNTU-CVE-2019-1010204
  │ ✔✘ CVE-2021-20197         MEDIUM       6.3   EPSS:0.00115
  │        ↳ O:UBUNTU-CVE-2021-20197
  │ ✔✔ CVE-2022-48064         MEDIUM       5.5   EPSS:0.00009       1
  │        ↳ O:UBUNTU-CVE-2022-48064
  │ ✔✘ CVE-2025-0840          HIGH         7.5   EPSS:0.00101       2
  │        ↳ O:USN-7899-1
  │ ✔✘ CVE-2025-11081         MEDIUM       5.5   EPSS:0.00026       2
  │        ↳ O:USN-7919-1
  │ ✔✘ CVE-2025-11082         HIGH         7.8   EPSS:0.00021       2
  │        ↳ O:UBUNTU-CVE-2025-11082,USN-7919-1
  │ ✔✘ CVE-2025-11083         HIGH         7.8   EPSS:0.00024       2
  │        ↳ O:UBUNTU-CVE-2025-11083,USN-7919-1
  │ ✔✘ CVE-2025-11412         MEDIUM       5.5   EPSS:0.00026       2
  │        ↳ O:UBUNTU-CVE-2025-11412,USN-7919-1
  │ ✔✘ CVE-2025-11413         MEDIUM       5.5   EPSS:0.00025       2
  │        ↳ O:UBUNTU-CVE-2025-11413,USN-7919-1
  │ ✔✘ CVE-2025-11414         MEDIUM       5.5   EPSS:0.00026       2
  │        ↳ O:UBUNTU-CVE-2025-11414,USN-7919-1
  │ ✔✔ CVE-2025-1148          LOW          3.1   EPSS:0.00072       2
  │        ↳ O:UBUNTU-CVE-2025-1148
  │ ✔✔ CVE-2025-1149          LOW          3.1   EPSS:0.00051       1
  │        ↳ O:UBUNTU-CVE-2025-1149
  │ ✔✘ CVE-2025-11494         MEDIUM       5.5   EPSS:0.00034       2
  │        ↳ O:UBUNTU-CVE-2025-11494,USN-7919-1
  │ ✔✘ CVE-2025-11495         MEDIUM       5.5   EPSS:0.00026       2
  │        ↳ O:UBUNTU-CVE-2025-11495,USN-7919-1
  │ ✔✔ CVE-2025-1150          LOW          3.1   EPSS:0.00048       1
  │        ↳ O:UBUNTU-CVE-2025-1150
  │ ✔✔ CVE-2025-1151          LOW          3.1   EPSS:0.00078       2
  │        ↳ O:UBUNTU-CVE-2025-1151
  │ ✔✔ CVE-2025-1152          LOW          3.7   EPSS:0.00051       1
  │        ↳ O:UBUNTU-CVE-2025-1152
  │ ✔✘ CVE-2025-1153          MEDIUM       5.9   EPSS:0.00087       2
  │        ↳ O:USN-7899-1
  │ ✔✘ CVE-2025-1178          MEDIUM       6.3   EPSS:0.00120       1
  │        ↳ O:UBUNTU-CVE-2025-1178
  │ ✘✔ CVE-2025-1179          HIGH         7.5   EPSS:0.00104       4
  │ ✔✔ CVE-2025-1180          LOW          3.1   EPSS:0.00082       1
  │        ↳ O:UBUNTU-CVE-2025-1180
  │ ✔✘ CVE-2025-1181          MEDIUM       5.1   EPSS:0.00117       1
  │        ↳ O:UBUNTU-CVE-2025-1181,USN-7899-1
  │ ✔✘ CVE-2025-1182          MEDIUM       5.1   EPSS:0.00104       2
  │        ↳ O:USN-7899-1
  │ ✔✘ CVE-2025-11839         MEDIUM       5.5   EPSS:0.00017       1
  │        ↳ O:UBUNTU-CVE-2025-11839,USN-7899-1
  │ ✔✘ CVE-2025-11840         MEDIUM       5.5   EPSS:0.00028       2
  │        ↳ O:UBUNTU-CVE-2025-11840,USN-7899-1
  │ ✔✔ CVE-2025-3198          MEDIUM       5.5   EPSS:0.00068       1
  │        ↳ O:UBUNTU-CVE-2025-3198,USN-7899-1
  │ ✔✔ CVE-2025-5244          HIGH         7.8   EPSS:0.00081       1
  │        ↳ O:UBUNTU-CVE-2025-5244,USN-7899-1
  │ ✔✔ CVE-2025-5245          HIGH         7.8   EPSS:0.00084       1
  │        ↳ O:UBUNTU-CVE-2025-5245,USN-7899-1
  │ ✔✘ CVE-2025-66861         LOW          2.5   EPSS:0.00023       1
  │        ↳ O:UBUNTU-CVE-2025-66861
  │ ✔✘ CVE-2025-66862         HIGH         7.5   EPSS:0.00076       1
  │        ↳ O:UBUNTU-CVE-2025-66862
  │ ✔✘ CVE-2025-66863         HIGH         7.5   EPSS:0.00076       1
  │        ↳ O:UBUNTU-CVE-2025-66863
  │ ✔✘ CVE-2025-66864         HIGH         7.5   EPSS:0.00049       1
  │        ↳ O:UBUNTU-CVE-2025-66864
  │ ✔✘ CVE-2025-66865         HIGH         7.5   EPSS:0.00076       1
  │        ↳ O:UBUNTU-CVE-2025-66865
  │ ✔✘ CVE-2025-66866         HIGH         7.5   EPSS:0.00016       2
  │        ↳ O:UBUNTU-CVE-2025-66866
  │ ✔✘ CVE-2025-69644         MEDIUM       5.0   EPSS:0.00005
  │        ↳ O:UBUNTU-CVE-2025-69644
  │ ✔✘ CVE-2025-69645         MEDIUM       5.5   EPSS:0.00004       1
  │        ↳ O:UBUNTU-CVE-2025-69645
  │ ✔✘ CVE-2025-69646         MEDIUM       5.5   EPSS:0.00005       1
  │        ↳ O:UBUNTU-CVE-2025-69646
  │ ✔✘ CVE-2025-69647         MEDIUM       6.2   EPSS:0.00016       1
  │        ↳ O:UBUNTU-CVE-2025-69647
  │ ✔✘ CVE-2025-69648         MEDIUM       6.2   EPSS:0.00015       1
  │        ↳ O:UBUNTU-CVE-2025-69648
  │ ✔✘ CVE-2025-69649         HIGH         7.5   EPSS:0.00030       1
  │        ↳ O:UBUNTU-CVE-2025-69649
  │ ✔✘ CVE-2025-69650         HIGH         7.5   EPSS:0.00101       1
  │        ↳ O:UBUNTU-CVE-2025-69650
  │ ✔✘ CVE-2025-69651         MEDIUM       5.5   EPSS:0.00005       1
  │        ↳ O:UBUNTU-CVE-2025-69651
  │ ✔✘ CVE-2025-69652         MEDIUM       6.2   EPSS:0.00015       1
  │        ↳ O:UBUNTU-CVE-2025-69652
  │ ✔✘ CVE-2025-7545          HIGH         7.8   EPSS:0.00023
  │        ↳ O:UBUNTU-CVE-2025-7545,USN-7899-1
  │ ✔✘ CVE-2025-8225          MEDIUM       4.8   EPSS:0.00024       1
  │        ↳ O:UBUNTU-CVE-2025-8225,USN-7899-1
  │ ✔✘ CVE-2026-3441          HIGH         7.1   EPSS:0.00005
  │        ↳ O:UBUNTU-CVE-2026-3441
  │ ✔✘ CVE-2026-3442          HIGH         7.1   EPSS:0.00005       1
  │        ↳ O:UBUNTU-CVE-2026-3442
  │ ✔✘ CVE-2026-4647          MEDIUM       6.1   EPSS:0.00012
  │        ↳ O:UBUNTU-CVE-2026-4647
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ binutils-common@2.34-6ubuntu1.11
  │ ✘✔ CVE-2017-13716         HIGH         7.1   EPSS:0.00237
  │ ✘✔ CVE-2019-1010204       MEDIUM       5.5   EPSS:0.00143
  │ ✘✔ CVE-2022-48064         MEDIUM       5.5   EPSS:0.00009       1
  │ ✘✔ CVE-2025-1148          LOW          3.1   EPSS:0.00072       2
  │ ✘✔ CVE-2025-1149          LOW          3.1   EPSS:0.00051       1
  │ ✘✔ CVE-2025-1150          LOW          3.1   EPSS:0.00048       1
  │ ✘✔ CVE-2025-1151          LOW          3.1   EPSS:0.00078       2
  │ ✘✔ CVE-2025-1152          LOW          3.7   EPSS:0.00051       1
  │ ✘✔ CVE-2025-1179          HIGH         7.5   EPSS:0.00104       4
  │ ✘✔ CVE-2025-1180          LOW          3.1   EPSS:0.00082       1
  │ ✘✔ CVE-2025-3198          MEDIUM       5.5   EPSS:0.00068       1
  │ ✘✔ CVE-2025-5244          HIGH         7.8   EPSS:0.00081       1
  │ ✘✔ CVE-2025-5245          HIGH         7.8   EPSS:0.00084       1
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ binutils-x86-64-linux-gnu@2.34-6ubuntu1.11
  │ ✘✔ CVE-2017-13716         HIGH         7.1   EPSS:0.00237
  │ ✘✔ CVE-2019-1010204       MEDIUM       5.5   EPSS:0.00143
  │ ✘✔ CVE-2022-48064         MEDIUM       5.5   EPSS:0.00009       1
  │ ✘✔ CVE-2025-1148          LOW          3.1   EPSS:0.00072       2
  │ ✘✔ CVE-2025-1149          LOW          3.1   EPSS:0.00051       1
  │ ✘✔ CVE-2025-1150          LOW          3.1   EPSS:0.00048       1
  │ ✘✔ CVE-2025-1151          LOW          3.1   EPSS:0.00078       2
  │ ✘✔ CVE-2025-1152          LOW          3.7   EPSS:0.00051       1
  │ ✘✔ CVE-2025-1179          HIGH         7.5   EPSS:0.00104       4
  │ ✘✔ CVE-2025-1180          LOW          3.1   EPSS:0.00082       1
  │ ✘✔ CVE-2025-3198          MEDIUM       5.5   EPSS:0.00068       1
  │ ✘✔ CVE-2025-5244          HIGH         7.8   EPSS:0.00081       1
  │ ✘✔ CVE-2025-5245          HIGH         7.8   EPSS:0.00084       1
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ coreutils@8.30-3ubuntu2
  │ ✔✔ CVE-2016-2781          MEDIUM       6.5   EPSS:0.00076
  │        ↳ O:UBUNTU-CVE-2016-2781
  │ ✔✔ CVE-2025-5278          MEDIUM       4.4   EPSS:0.00063
  │        ↳ O:UBUNTU-CVE-2025-5278
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ cpp-9@9.4.0-1ubuntu1~20.04.2
  │ ✘✔ CVE-2023-4039          MEDIUM       4.8   EPSS:0.00186       2
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ curl@7.68.0-1ubuntu2.25
  │ ✔✘ CVE-2025-14017         MEDIUM       6.3   EPSS:0.00007
  │        ↳ O:UBUNTU-CVE-2025-14017,USN-8062-2
  │ ✔✘ CVE-2025-14524         MEDIUM       5.3   EPSS:0.00026       1
  │        ↳ O:UBUNTU-CVE-2025-14524
  │ ✔✘ CVE-2025-15079         MEDIUM       5.3   EPSS:0.00035       1
  │        ↳ O:UBUNTU-CVE-2025-15079,USN-8062-2
  │ ✔✘ CVE-2025-15224         LOW          3.1   EPSS:0.00084       1
  │        ↳ O:UBUNTU-CVE-2025-15224,USN-8062-2
  │ ✔✘ CVE-2026-1965          MEDIUM       6.5   EPSS:0.00054
  │        ↳ O:UBUNTU-CVE-2026-1965,USN-8099-1
  │ ✔✘ CVE-2026-3783          MEDIUM       5.3   EPSS:0.00016       1
  │        ↳ O:UBUNTU-CVE-2026-3783,USN-8099-1
  │ ✔✘ CVE-2026-3784          MEDIUM       6.5   EPSS:0.00015       1
  │        ↳ O:UBUNTU-CVE-2026-3784,USN-8099-1
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ dbus@1.12.16-2ubuntu2.3
  │ ✔✔ CVE-2023-34969         MEDIUM       6.5   EPSS:0.00629       1
  │        ↳ O:UBUNTU-CVE-2023-34969
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ dbus-user-session@1.12.16-2ubuntu2.3
  │ ✘✔ CVE-2023-34969         MEDIUM       6.5   EPSS:0.00629       1
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ dirmngr@2.2.19-3ubuntu2.5
  │ ✘✔ CVE-2022-3219          LOW          3.3   EPSS:0.00015
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ dpkg@1.19.7ubuntu3.2
  │ ✔✘ CVE-2025-6297          HIGH         8.2   EPSS:0.00078
  │        ↳ O:UBUNTU-CVE-2025-6297
  │ ✔✘ CVE-2026-2219          HIGH         7.5   EPSS:0.00021
  │        ↳ O:UBUNTU-CVE-2026-2219
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ g++-9@9.4.0-1ubuntu1~20.04.2
  │ ✘✔ CVE-2023-4039          MEDIUM       4.8   EPSS:0.00186       2
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ gcc-10-base@10.5.0-1ubuntu1~20.04
  │ ✘✔ CVE-2023-4039          MEDIUM       4.8   EPSS:0.00186       2
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ gcc-9@9.4.0-1ubuntu1~20.04.2
  │ ✔✘ CVE-2020-23026         HIGH         7.5   EPSS:0.00336
  │        ↳ O:UBUNTU-CVE-2020-23026
  │ ✔✔ CVE-2023-4039          MEDIUM       4.8   EPSS:0.00186       2
  │        ↳ O:UBUNTU-CVE-2023-4039
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ gcc-9-base@9.4.0-1ubuntu1~20.04.2
  │ ✘✔ CVE-2023-4039          MEDIUM       4.8   EPSS:0.00186       2
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ gir1.2-packagekitglib-1.0@1.1.13-2ubuntu1.1
  │ ✘✔ CVE-2022-0987          LOW          3.3   EPSS:0.00041
  │ ✘✔ CVE-2024-0217          LOW          3.3   EPSS:0.00013
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ gnupg@2.2.19-3ubuntu2.5
  │ ✘✔ CVE-2022-3219          LOW          3.3   EPSS:0.00015
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ gnupg-l10n@2.2.19-3ubuntu2.5
  │ ✘✔ CVE-2022-3219          LOW          3.3   EPSS:0.00015
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ gnupg-utils@2.2.19-3ubuntu2.5
  │ ✘✔ CVE-2022-3219          LOW          3.3   EPSS:0.00015
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ gpg@2.2.19-3ubuntu2.5
  │ ✘✔ CVE-2022-3219          LOW          3.3   EPSS:0.00015
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ gpg-agent@2.2.19-3ubuntu2.5
  │ ✘✔ CVE-2022-3219          LOW          3.3   EPSS:0.00015
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ gpg-wks-client@2.2.19-3ubuntu2.5
  │ ✘✔ CVE-2022-3219          LOW          3.3   EPSS:0.00015
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ gpg-wks-server@2.2.19-3ubuntu2.5
  │ ✘✔ CVE-2022-3219          LOW          3.3   EPSS:0.00015
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ gpgconf@2.2.19-3ubuntu2.5
  │ ✘✔ CVE-2022-3219          LOW          3.3   EPSS:0.00015
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ gpgsm@2.2.19-3ubuntu2.5
  │ ✘✔ CVE-2022-3219          LOW          3.3   EPSS:0.00015
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ gpgv@2.2.19-3ubuntu2.5
  │ ✘✔ CVE-2022-3219          LOW          3.3   EPSS:0.00015
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ libasan5@9.4.0-1ubuntu1~20.04.2
  │ ✘✔ CVE-2023-4039          MEDIUM       4.8   EPSS:0.00186       2
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ libatomic1@10.5.0-1ubuntu1~20.04
  │ ✘✔ CVE-2023-4039          MEDIUM       4.8   EPSS:0.00186       2
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ libbinutils@2.34-6ubuntu1.11
  │ ✘✔ CVE-2017-13716         HIGH         7.1   EPSS:0.00237
  │ ✘✔ CVE-2019-1010204       MEDIUM       5.5   EPSS:0.00143
  │ ✘✔ CVE-2022-48064         MEDIUM       5.5   EPSS:0.00009       1
  │ ✘✔ CVE-2025-1148          LOW          3.1   EPSS:0.00072       2
  │ ✘✔ CVE-2025-1149          LOW          3.1   EPSS:0.00051       1
  │ ✘✔ CVE-2025-1150          LOW          3.1   EPSS:0.00048       1
  │ ✘✔ CVE-2025-1151          LOW          3.1   EPSS:0.00078       2
  │ ✘✔ CVE-2025-1152          LOW          3.7   EPSS:0.00051       1
  │ ✘✔ CVE-2025-1179          HIGH         7.5   EPSS:0.00104       4
  │ ✘✔ CVE-2025-1180          LOW          3.1   EPSS:0.00082       1
  │ ✘✔ CVE-2025-3198          MEDIUM       5.5   EPSS:0.00068       1
  │ ✘✔ CVE-2025-5244          HIGH         7.8   EPSS:0.00081       1
  │ ✘✔ CVE-2025-5245          HIGH         7.8   EPSS:0.00084       1
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ libc-bin@2.31-0ubuntu9.17
  │ ✘✔ CVE-2016-20013         HIGH         7.5   EPSS:0.00307       2
  │ ✘✔ CVE-2025-4802          HIGH         7.8   EPSS:0.00043       1
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ libc-dev-bin@2.31-0ubuntu9.18
  │ ✘✔ CVE-2016-20013         HIGH         7.5   EPSS:0.00307       2
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ libc6@2.31-0ubuntu9.18
  │ ✘✔ CVE-2016-20013         HIGH         7.5   EPSS:0.00307       2
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ libc6-dev@2.31-0ubuntu9.18
  │ ✘✔ CVE-2016-20013         HIGH         7.5   EPSS:0.00307       2
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ libcc1-0@10.5.0-1ubuntu1~20.04
  │ ✘✔ CVE-2023-4039          MEDIUM       4.8   EPSS:0.00186       2
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ libctf-nobfd0@2.34-6ubuntu1.11
  │ ✘✔ CVE-2017-13716         HIGH         7.1   EPSS:0.00237
  │ ✘✔ CVE-2019-1010204       MEDIUM       5.5   EPSS:0.00143
  │ ✘✔ CVE-2022-48064         MEDIUM       5.5   EPSS:0.00009       1
  │ ✘✔ CVE-2025-1148          LOW          3.1   EPSS:0.00072       2
  │ ✘✔ CVE-2025-1149          LOW          3.1   EPSS:0.00051       1
  │ ✘✔ CVE-2025-1150          LOW          3.1   EPSS:0.00048       1
  │ ✘✔ CVE-2025-1151          LOW          3.1   EPSS:0.00078       2
  │ ✘✔ CVE-2025-1152          LOW          3.7   EPSS:0.00051       1
  │ ✘✔ CVE-2025-1179          HIGH         7.5   EPSS:0.00104       4
  │ ✘✔ CVE-2025-1180          LOW          3.1   EPSS:0.00082       1
  │ ✘✔ CVE-2025-3198          MEDIUM       5.5   EPSS:0.00068       1
  │ ✘✔ CVE-2025-5244          HIGH         7.8   EPSS:0.00081       1
  │ ✘✔ CVE-2025-5245          HIGH         7.8   EPSS:0.00084       1
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ libctf0@2.34-6ubuntu1.11
  │ ✘✔ CVE-2017-13716         HIGH         7.1   EPSS:0.00237
  │ ✘✔ CVE-2019-1010204       MEDIUM       5.5   EPSS:0.00143
  │ ✘✔ CVE-2022-48064         MEDIUM       5.5   EPSS:0.00009       1
  │ ✘✔ CVE-2025-1148          LOW          3.1   EPSS:0.00072       2
  │ ✘✔ CVE-2025-1149          LOW          3.1   EPSS:0.00051       1
  │ ✘✔ CVE-2025-1150          LOW          3.1   EPSS:0.00048       1
  │ ✘✔ CVE-2025-1151          LOW          3.1   EPSS:0.00078       2
  │ ✘✔ CVE-2025-1152          LOW          3.7   EPSS:0.00051       1
  │ ✘✔ CVE-2025-1179          HIGH         7.5   EPSS:0.00104       4
  │ ✘✔ CVE-2025-1180          LOW          3.1   EPSS:0.00082       1
  │ ✘✔ CVE-2025-3198          MEDIUM       5.5   EPSS:0.00068       1
  │ ✘✔ CVE-2025-5244          HIGH         7.8   EPSS:0.00081       1
  │ ✘✔ CVE-2025-5245          HIGH         7.8   EPSS:0.00084       1
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ libdbus-1-3@1.12.16-2ubuntu2.3
  │ ✘✔ CVE-2023-34969         MEDIUM       6.5   EPSS:0.00629       1
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ libelf1@0.176-1.1ubuntu0.1
  │ ✘✔ CVE-2025-1352          HIGH         7.5   EPSS:0.00121       1
  │ ✘✔ CVE-2025-1376          MEDIUM       4.7   EPSS:0.00010       3
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ libgcc-9-dev@9.4.0-1ubuntu1~20.04.2
  │ ✘✔ CVE-2023-4039          MEDIUM       4.8   EPSS:0.00186       2
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ libgcc-s1@10.5.0-1ubuntu1~20.04
  │ ✘✔ CVE-2023-4039          MEDIUM       4.8   EPSS:0.00186       2
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ libgcrypt20@1.8.5-5ubuntu1.1
  │ ✔✔ CVE-2024-2236          MEDIUM       5.9   EPSS:0.00745
  │        ↳ O:UBUNTU-CVE-2024-2236
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ libglib2.0-0@2.64.6-1~ubuntu20.04.9
  │ ✘✔ CVE-2025-3360          LOW          3.7   EPSS:0.00392
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ libglib2.0-bin@2.64.6-1~ubuntu20.04.9
  │ ✘✔ CVE-2025-3360          LOW          3.7   EPSS:0.00392
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ libglib2.0-data@2.64.6-1~ubuntu20.04.9
  │ ✘✔ CVE-2025-3360          LOW          3.7   EPSS:0.00392
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ libgomp1@10.5.0-1ubuntu1~20.04
  │ ✘✔ CVE-2023-4039          MEDIUM       4.8   EPSS:0.00186       2
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ libicu66@66.1-2ubuntu2.1
  │ ✘✔ CVE-2025-5222          HIGH         7.0   EPSS:0.00046
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ libitm1@10.5.0-1ubuntu1~20.04
  │ ✘✔ CVE-2023-4039          MEDIUM       4.8   EPSS:0.00186       2
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ liblsan0@10.5.0-1ubuntu1~20.04
  │ ✘✔ CVE-2023-4039          MEDIUM       4.8   EPSS:0.00186       2
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ libncurses6@6.2-0ubuntu2.1
  │ ✘✔ CVE-2023-45918 [R]     REJECTED     0.0
  │ ✘✔ CVE-2023-50495         MEDIUM       6.5   EPSS:0.00051
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ libncursesw6@6.2-0ubuntu2.1
  │ ✘✔ CVE-2023-45918 [R]     REJECTED     0.0
  │ ✘✔ CVE-2023-50495         MEDIUM       6.5   EPSS:0.00051
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ libnss-systemd@245.4-4ubuntu3.24
  │ ✘✔ CVE-2023-26604         HIGH         7.8   EPSS:0.05624       5
  │ ✘✔ CVE-2023-7008          MEDIUM       5.9   EPSS:0.00439
  │ ✘✔ CVE-2025-4598          MEDIUM       4.7   EPSS:0.00100       2
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ libpackagekit-glib2-18@1.1.13-2ubuntu1.1
  │ ✘✔ CVE-2022-0987          LOW          3.3   EPSS:0.00041
  │ ✘✔ CVE-2024-0217          LOW          3.3   EPSS:0.00013
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ libpam-modules@1.3.1-5ubuntu4.7
  │ ✘✔ CVE-2024-10041         MEDIUM       4.7   EPSS:0.00043
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ libpam-modules-bin@1.3.1-5ubuntu4.7
  │ ✘✔ CVE-2024-10041         MEDIUM       4.7   EPSS:0.00043
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ libpam-runtime@1.3.1-5ubuntu4.7
  │ ✘✔ CVE-2024-10041         MEDIUM       4.7   EPSS:0.00043
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ libpam-systemd@245.4-4ubuntu3.24
  │ ✘✔ CVE-2023-26604         HIGH         7.8   EPSS:0.05624       5
  │ ✘✔ CVE-2023-7008          MEDIUM       5.9   EPSS:0.00439
  │ ✘✔ CVE-2025-4598          MEDIUM       4.7   EPSS:0.00100       2
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ libpam0g@1.3.1-5ubuntu4.7
  │ ✘✔ CVE-2024-10041         MEDIUM       4.7   EPSS:0.00043
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ libpcre2-8-0@10.34-7ubuntu0.1
  │ ✘✔ CVE-2022-41409         HIGH         7.5   EPSS:0.00046       1
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ libpcre3@2:8.39-12ubuntu0.1
  │ ✘✔ CVE-2017-11164         HIGH         7.8   EPSS:0.00106
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ libperl5.30@5.30.0-9ubuntu0.5
  │ ✘✔ CVE-2025-40909         MEDIUM       5.9   EPSS:0.00041
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ libpolkit-agent-1-0@0.105-26ubuntu1.3
  │ ✘✔ CVE-2016-2568          HIGH         7.8   EPSS:0.00131
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ libpolkit-gobject-1-0@0.105-26ubuntu1.3
  │ ✘✔ CVE-2016-2568          HIGH         7.8   EPSS:0.00131
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ libpython3.8@3.8.10-0ubuntu1~20.04.18
  │ ✘✔ CVE-2025-1795          LOW          2.3   EPSS:0.00593
  │ ✘✔ CVE-2025-4516          MEDIUM       5.9   EPSS:0.00209
  │ ✘✔ CVE-2025-6069          MEDIUM       4.3   EPSS:0.00283
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ libpython3.8-dev@3.8.10-0ubuntu1~20.04.18
  │ ✘✔ CVE-2025-1795          LOW          2.3   EPSS:0.00593
  │ ✘✔ CVE-2025-4516          MEDIUM       5.9   EPSS:0.00209
  │ ✘✔ CVE-2025-6069          MEDIUM       4.3   EPSS:0.00283
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ libpython3.8-minimal@3.8.10-0ubuntu1~20.04.18
  │ ✘✔ CVE-2025-1795          LOW          2.3   EPSS:0.00593
  │ ✘✔ CVE-2025-4516          MEDIUM       5.9   EPSS:0.00209
  │ ✘✔ CVE-2025-6069          MEDIUM       4.3   EPSS:0.00283
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ libpython3.8-stdlib@3.8.10-0ubuntu1~20.04.18
  │ ✘✔ CVE-2025-1795          LOW          2.3   EPSS:0.00593
  │ ✘✔ CVE-2025-4516          MEDIUM       5.9   EPSS:0.00209
  │ ✘✔ CVE-2025-6069          MEDIUM       4.3   EPSS:0.00283
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ libquadmath0@10.5.0-1ubuntu1~20.04
  │ ✘✔ CVE-2023-4039          MEDIUM       4.8   EPSS:0.00186       2
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ libsoup2.4-1@2.70.0-1ubuntu0.5
  │ ✘✔ CVE-2025-32049         HIGH         7.5   EPSS:0.01560
  │ ✘✔ CVE-2025-32907         MEDIUM       5.3   EPSS:0.00989
  │ ✘✔ CVE-2025-4035          MEDIUM       4.3   EPSS:0.00193
  │ ✘✔ CVE-2025-4945          LOW          3.7   EPSS:0.00296
  │ ✘✔ CVE-2025-4948          HIGH         7.5   EPSS:0.00986
  │ ✘✔ CVE-2025-4969          MEDIUM       6.5   EPSS:0.00568
  │ ✘✔ CVE-2025-8197 [R]      REJECTED     0.0
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ libstdc++-9-dev@9.4.0-1ubuntu1~20.04.2
  │ ✘✔ CVE-2023-4039          MEDIUM       4.8   EPSS:0.00186       2
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ libstdc++6@10.5.0-1ubuntu1~20.04
  │ ✘✔ CVE-2023-4039          MEDIUM       4.8   EPSS:0.00186       2
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ libsystemd0@245.4-4ubuntu3.24
  │ ✘✔ CVE-2023-26604         HIGH         7.8   EPSS:0.05624       5
  │ ✘✔ CVE-2023-7008          MEDIUM       5.9   EPSS:0.00439
  │ ✘✔ CVE-2025-4598          MEDIUM       4.7   EPSS:0.00100       2
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ libtasn1-6@4.16.0-2ubuntu0.1
  │ ✔✔ CVE-2021-46848         CRITICAL     9.1   EPSS:0.00369       1
  │        ↳ O:UBUNTU-CVE-2021-46848,USN-7954-2
  │ ✔✘ CVE-2025-13151         HIGH         7.5   EPSS:0.00062
  │        ↳ O:UBUNTU-CVE-2025-13151,USN-7954-2
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ libtinfo6@6.2-0ubuntu2.1
  │ ✘✔ CVE-2023-45918 [R]     REJECTED     0.0
  │ ✘✔ CVE-2023-50495         MEDIUM       6.5   EPSS:0.00051
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ libtsan0@10.5.0-1ubuntu1~20.04
  │ ✘✔ CVE-2023-4039          MEDIUM       4.8   EPSS:0.00186       2
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ libubsan1@10.5.0-1ubuntu1~20.04
  │ ✘✔ CVE-2023-4039          MEDIUM       4.8   EPSS:0.00186       2
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ libudev1@245.4-4ubuntu3.24
  │ ✘✔ CVE-2023-26604         HIGH         7.8   EPSS:0.05624       5
  │ ✘✔ CVE-2023-7008          MEDIUM       5.9   EPSS:0.00439
  │ ✘✔ CVE-2025-4598          MEDIUM       4.7   EPSS:0.00100       2
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ libxml2@2.9.10+dfsg-5ubuntu0.20.04.10
  │ ✔✘ CVE-2025-26434         MEDIUM       5.5   EPSS:0.00006
  │        ↳ O:UBUNTU-CVE-2025-26434
  │ ✔✘ CVE-2025-49794         CRITICAL     9.1   EPSS:0.00123
  │        ↳ O:UBUNTU-CVE-2025-49794,USN-7694-1
  │ ✔✘ CVE-2025-49796         CRITICAL     9.1   EPSS:0.00496
  │        ↳ O:UBUNTU-CVE-2025-49796,USN-7694-1
  │ ✔✘ CVE-2025-6021          HIGH         7.5   EPSS:0.00759       1
  │        ↳ O:UBUNTU-CVE-2025-6021,USN-7694-1
  │ ✔✘ CVE-2025-6170          LOW          2.5   EPSS:0.00034
  │        ↳ O:UBUNTU-CVE-2025-6170,USN-7694-1
  │ ✔✘ CVE-2025-7425          HIGH         7.8   EPSS:0.00054       1
  │        ↳ O:UBUNTU-CVE-2025-7425,USN-7852-2
  │ ✔✘ CVE-2025-8732          MEDIUM       4.8   EPSS:0.00015
  │        ↳ O:UBUNTU-CVE-2025-8732,USN-7974-1
  │ ✔✘ CVE-2025-9714          MEDIUM       6.2   EPSS:0.00009
  │        ↳ O:UBUNTU-CVE-2025-9714,USN-7743-1
  │ ✔✘ CVE-2026-0989          LOW          3.7   EPSS:0.00020
  │        ↳ O:UBUNTU-CVE-2026-0989,USN-7974-1
  │ ✔✘ CVE-2026-0990          MEDIUM       5.9   EPSS:0.00060
  │        ↳ O:UBUNTU-CVE-2026-0990,USN-7974-1
  │ ✔✘ CVE-2026-0992          LOW          2.9   EPSS:0.00023
  │        ↳ O:UBUNTU-CVE-2026-0992,USN-7974-1
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ login@1:4.8.1-1ubuntu5.20.04.5
  │ ✘✔ CVE-2013-4235          MEDIUM       4.7   EPSS:0.00058
  │ ✘✔ CVE-2023-29383         LOW          3.3   EPSS:0.00025       2
  │ ✘✔ CVE-2024-56433         LOW          3.6   EPSS:0.04509
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ ncurses-base@6.2-0ubuntu2.1
  │ ✘✔ CVE-2023-45918 [R]     REJECTED     0.0
  │ ✘✔ CVE-2023-50495         MEDIUM       6.5   EPSS:0.00051
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ ncurses-bin@6.2-0ubuntu2.1
  │ ✘✔ CVE-2023-45918 [R]     REJECTED     0.0
  │ ✘✔ CVE-2023-50495         MEDIUM       6.5   EPSS:0.00051
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ openssl@1.1.1f-1ubuntu2.24
  │ ✔✘ CVE-2025-68160         MEDIUM       4.7   EPSS:0.00024       1
  │        ↳ O:UBUNTU-CVE-2025-68160,USN-7980-2
  │ ✔✘ CVE-2025-69418         MEDIUM       4.0   EPSS:0.00007       1
  │        ↳ O:UBUNTU-CVE-2025-69418,USN-7980-2
  │ ✔✘ CVE-2025-69419         HIGH         7.4   EPSS:0.00060       1
  │        ↳ O:UBUNTU-CVE-2025-69419,USN-7980-2
  │ ✔✘ CVE-2025-69420         HIGH         7.5   EPSS:0.00290       1
  │        ↳ O:UBUNTU-CVE-2025-69420,USN-7980-2
  │ ✔✘ CVE-2025-69421         HIGH         7.5   EPSS:0.00034       1
  │        ↳ O:UBUNTU-CVE-2025-69421,USN-7980-2
  │ ✔✘ CVE-2025-9230          HIGH         7.5   EPSS:0.00034
  │        ↳ O:UBUNTU-CVE-2025-9230,USN-7786-1
  │ ✔✘ CVE-2025-9231          MEDIUM       6.5   EPSS:0.00022
  │        ↳ O:USN-7786-1
  │ ✔✘ CVE-2025-9232          MEDIUM       5.9   EPSS:0.00036
  │        ↳ O:USN-7786-1
  │ ✔✘ CVE-2026-22795         MEDIUM       5.5   EPSS:0.00024       1
  │        ↳ O:UBUNTU-CVE-2026-22795,USN-7980-2
  │ ✔✘ CVE-2026-22796         MEDIUM       5.3   EPSS:0.00112       1
  │        ↳ O:UBUNTU-CVE-2026-22796,USN-7980-2
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ packagekit@1.1.13-2ubuntu1.1
  │ ✔✔ CVE-2022-0987          LOW          3.3   EPSS:0.00041
  │        ↳ O:UBUNTU-CVE-2022-0987
  │ ✔✔ CVE-2024-0217          LOW          3.3   EPSS:0.00013
  │        ↳ O:UBUNTU-CVE-2024-0217
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ packagekit-tools@1.1.13-2ubuntu1.1
  │ ✘✔ CVE-2022-0987          LOW          3.3   EPSS:0.00041
  │ ✘✔ CVE-2024-0217          LOW          3.3   EPSS:0.00013
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ passwd@1:4.8.1-1ubuntu5.20.04.5
  │ ✘✔ CVE-2013-4235          MEDIUM       4.7   EPSS:0.00058
  │ ✘✔ CVE-2023-29383         LOW          3.3   EPSS:0.00025       2
  │ ✘✔ CVE-2024-56433         LOW          3.6   EPSS:0.04509
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ patch@2.7.6-6
  │ ✔✔ CVE-2018-6952          HIGH         7.5   EPSS:0.11805
  │        ↳ O:UBUNTU-CVE-2018-6952
  │ ✔✔ CVE-2019-20633         MEDIUM       5.5   EPSS:0.11805       1
  │        ↳ O:UBUNTU-CVE-2019-20633
  │ ✔✔ CVE-2021-45261         MEDIUM       5.5   EPSS:0.00197       1
  │        ↳ O:UBUNTU-CVE-2021-45261
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ perl@5.30.0-9ubuntu0.5
  │ ✔✘ CVE-2023-31486         HIGH         8.1   EPSS:0.00598
  │        ↳ O:UBUNTU-CVE-2023-31486
  │ ✔✘ CVE-2023-47039         HIGH         7.8   EPSS:0.00089
  │        ↳ O:UBUNTU-CVE-2023-47039
  │ ✔✔ CVE-2025-40909         MEDIUM       5.9   EPSS:0.00041
  │        ↳ O:UBUNTU-CVE-2025-40909
  │ ✔✘ CVE-2026-3381          CRITICAL     9.8   EPSS:0.00007       1
  │        ↳ O:UBUNTU-CVE-2026-3381
  │ ✔✘ CVE-2026-4176          CRITICAL     9.8   EPSS:0.00007       1
  │        ↳ O:UBUNTU-CVE-2026-4176
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ perl-base@5.30.0-9ubuntu0.5
  │ ✘✔ CVE-2025-40909         MEDIUM       5.9   EPSS:0.00041
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ perl-modules-5.30@5.30.0-9ubuntu0.5
  │ ✘✔ CVE-2025-40909         MEDIUM       5.9   EPSS:0.00041
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ policykit-1@0.105-26ubuntu1.3
  │ ✔✔ CVE-2016-2568          HIGH         7.8   EPSS:0.00131
  │        ↳ O:UBUNTU-CVE-2016-2568
  │ ✔✘ CVE-2025-7519          MEDIUM       6.7   EPSS:0.00012
  │        ↳ O:UBUNTU-CVE-2025-7519
  │ ✔✘ CVE-2026-4897          MEDIUM       5.5   EPSS:0.00014
  │        ↳ O:UBUNTU-CVE-2026-4897
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ python-apt-common@2.0.1ubuntu0.20.04.1
  │ ✘✔ CVE-2025-6966          MEDIUM       6.9   EPSS:0.00018       1
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ python-pip-whl@20.0.2-5ubuntu1.11
  │ ✘✔ CVE-2024-3651          HIGH         7.5   EPSS:0.00670       1
  │ ✘✔ CVE-2024-6345          HIGH         8.8   EPSS:0.07336
  │ ✘✔ CVE-2025-47273         HIGH         8.8   EPSS:0.00487       5
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ python3-apt@2.0.1ubuntu0.20.04.1
  │ ✘✔ CVE-2025-6966          MEDIUM       6.9   EPSS:0.00018       1
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ python3-pip@20.0.2-5ubuntu1.11
  │ ✘✔ CVE-2024-3651          HIGH         7.5   EPSS:0.00670       1
  │ ✘✔ CVE-2024-6345          HIGH         8.8   EPSS:0.07336
  │ ✘✔ CVE-2025-47273         HIGH         8.8   EPSS:0.00487       5
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ python3.8@3.8.10-0ubuntu1~20.04.18
  │ ✔✘ CVE-2007-4559          CRITICAL     9.8   EPSS:0.00126       3
  │        ↳ O:UBUNTU-CVE-2007-4559
  │ ✔✘ CVE-2020-10735         HIGH         7.5   EPSS:0.00395
  │        ↳ O:UBUNTU-CVE-2020-10735
  │ ✔✘ CVE-2021-23336         MEDIUM       5.9   EPSS:0.00311       1
  │        ↳ O:UBUNTU-CVE-2021-23336
  │ ✔✘ CVE-2025-11468         MEDIUM       5.7   EPSS:0.00039
  │        ↳ O:UBUNTU-CVE-2025-11468,USN-8018-1
  │ ✔✘ CVE-2025-12084         MEDIUM       6.3   EPSS:0.00049
  │        ↳ O:UBUNTU-CVE-2025-12084,USN-8018-1
  │ ✔✘ CVE-2025-12781         MEDIUM       6.3   EPSS:0.00018       1
  │        ↳ O:UBUNTU-CVE-2025-12781
  │ ✔✘ CVE-2025-13462         LOW          2.0   EPSS:0.00012
  │        ↳ O:UBUNTU-CVE-2025-13462
  │ ✔✘ CVE-2025-13836         HIGH         7.5   EPSS:0.00196
  │        ↳ O:UBUNTU-CVE-2025-13836,USN-7951-1
  │ ✔✘ CVE-2025-13837         MEDIUM       5.5   EPSS:0.00036
  │        ↳ O:UBUNTU-CVE-2025-13837,USN-8018-1
  │ ✔✘ CVE-2025-15282         MEDIUM       6.0   EPSS:0.00044
  │        ↳ O:UBUNTU-CVE-2025-15282,USN-8018-1
  │ ✔✘ CVE-2025-15366         MEDIUM       5.9   EPSS:0.00081
  │        ↳ O:UBUNTU-CVE-2025-15366,USN-8018-1,USN-8018-2
  │ ✔✘ CVE-2025-15367         MEDIUM       5.9   EPSS:0.00081
  │        ↳ O:UBUNTU-CVE-2025-15367,USN-8018-1,USN-8018-2
  │ ✔✔ CVE-2025-1795          LOW          2.3   EPSS:0.00593
  │        ↳ O:UBUNTU-CVE-2025-1795,USN-7570-1
  │ ✔✔ CVE-2025-4516          MEDIUM       5.9   EPSS:0.00209
  │        ↳ O:UBUNTU-CVE-2025-4516,USN-7570-1
  │ ✔✔ CVE-2025-6069          MEDIUM       4.3   EPSS:0.00283
  │        ↳ O:UBUNTU-CVE-2025-6069,USN-7710-1
  │ ✔✘ CVE-2025-6075          MEDIUM       5.5   EPSS:0.00021
  │        ↳ O:UBUNTU-CVE-2025-6075,USN-7886-1
  │ ✔✘ CVE-2025-69534         HIGH         7.5   EPSS:0.00249       1
  │        ↳ O:UBUNTU-CVE-2025-69534
  │ ✔✘ CVE-2025-8194          HIGH         7.5   EPSS:0.00190
  │        ↳ O:UBUNTU-CVE-2025-8194,USN-7710-1
  │ ✔✘ CVE-2025-8291          MEDIUM       4.3   EPSS:0.00114
  │        ↳ O:UBUNTU-CVE-2025-8291,USN-7886-1
  │ ✔✘ CVE-2026-0672          MEDIUM       6.0   EPSS:0.00158
  │        ↳ O:UBUNTU-CVE-2026-0672,USN-8018-1
  │ ✔✘ CVE-2026-0865          MEDIUM       5.9   EPSS:0.00132
  │        ↳ O:UBUNTU-CVE-2026-0865,USN-8018-1,USN-8018-2
  │ ✔✘ CVE-2026-1299          MEDIUM       6.0   EPSS:0.00238
  │        ↳ O:UBUNTU-CVE-2026-1299
  │ ✔✘ CVE-2026-2297          MEDIUM       5.7   EPSS:0.00016
  │        ↳ O:UBUNTU-CVE-2026-2297
  │ ✔✘ CVE-2026-3479          LOW          2.1   EPSS:0.00007
  │        ↳ O:UBUNTU-CVE-2026-3479
  │ ✔✘ CVE-2026-3644          MEDIUM       6.0   EPSS:0.00158
  │        ↳ O:UBUNTU-CVE-2026-3644
  │ ✔✘ CVE-2026-4224          MEDIUM       6.0   EPSS:0.00019
  │        ↳ O:UBUNTU-CVE-2026-4224
  │ ✔✘ CVE-2026-4519          HIGH         7.0   EPSS:0.00033
  │        ↳ O:UBUNTU-CVE-2026-4519
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ python3.8-dev@3.8.10-0ubuntu1~20.04.18
  │ ✘✔ CVE-2025-1795          LOW          2.3   EPSS:0.00593
  │ ✘✔ CVE-2025-4516          MEDIUM       5.9   EPSS:0.00209
  │ ✘✔ CVE-2025-6069          MEDIUM       4.3   EPSS:0.00283
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ python3.8-minimal@3.8.10-0ubuntu1~20.04.18
  │ ✘✔ CVE-2025-1795          LOW          2.3   EPSS:0.00593
  │ ✘✔ CVE-2025-4516          MEDIUM       5.9   EPSS:0.00209
  │ ✘✔ CVE-2025-6069          MEDIUM       4.3   EPSS:0.00283
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ systemd@245.4-4ubuntu3.24
  │ ✔✘ CVE-2020-13776         MEDIUM       6.7   EPSS:0.00258
  │        ↳ O:UBUNTU-CVE-2020-13776
  │ ✔✔ CVE-2023-26604         HIGH         7.8   EPSS:0.05624       5
  │        ↳ O:UBUNTU-CVE-2023-26604
  │ ✔✔ CVE-2023-7008          MEDIUM       5.9   EPSS:0.00439
  │        ↳ O:UBUNTU-CVE-2023-7008
  │ ✔✔ CVE-2025-4598          MEDIUM       4.7   EPSS:0.00100       2
  │        ↳ O:UBUNTU-CVE-2025-4598,USN-7559-1
  │ ✔✘ CVE-2026-29111         MEDIUM       5.5   EPSS:0.00011
  │        ↳ O:UBUNTU-CVE-2026-29111,USN-8119-2
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ systemd-sysv@245.4-4ubuntu3.24
  │ ✘✔ CVE-2023-26604         HIGH         7.8   EPSS:0.05624       5
  │ ✘✔ CVE-2023-7008          MEDIUM       5.9   EPSS:0.00439
  │ ✘✔ CVE-2025-4598          MEDIUM       4.7   EPSS:0.00100       2
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ systemd-timesyncd@245.4-4ubuntu3.24
  │ ✘✔ CVE-2023-26604         HIGH         7.8   EPSS:0.05624       5
  │ ✘✔ CVE-2023-7008          MEDIUM       5.9   EPSS:0.00439
  │ ✘✔ CVE-2025-4598          MEDIUM       4.7   EPSS:0.00100       2
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ tar@1.30+dfsg-7ubuntu0.20.04.4
  │ ✔✘ CVE-2025-45582         MEDIUM       4.1   EPSS:0.00073       1
  │        ↳ O:UBUNTU-CVE-2025-45582
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ util-linux@2.34-0.1ubuntu9.6
  │ ✔✘ CVE-2025-14104         MEDIUM       6.1   EPSS:0.00006
  │        ↳ O:UBUNTU-CVE-2025-14104
  │ ✔✘ USN-8091-1             ?            -                        n/a
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ xz-utils@5.2.4-1ubuntu1.1
  │ ✔✘ CVE-2026-34743         MEDIUM       6.3
  │        ↳ O:UBUNTU-CVE-2026-34743
  └────────────────────────────────────────────────────────────────────────────────

  ━━ Go ━━
  ┌─ github.com/containerd/containerd/v2@v2.0.4
  │ ✔✔ CVE-2024-25621         HIGH         7.8   EPSS:0.00006       1
  │        ↳ O:GHSA-pwhc-rpq9-4c8w,GO-2025-4100
  │ ✔✔ CVE-2025-47291         HIGH         7.5   EPSS:0.00270
  │        ↳ O:GHSA-cxfp-7pvr-95ff,GO-2025-3701
  │ ✔✔ CVE-2025-64329         MEDIUM       6.9   EPSS:0.00008       1
  │        ↳ O:GHSA-m6hq-p25p-ffr2,GO-2025-4108
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ github.com/docker/buildx@UNKNOWN
  │ ✔✘ CVE-2025-0495          MEDIUM       4.1   EPSS:0.00039
  │        ↳ O:GHSA-m4gq-fm9h-8q75,GO-2025-3527
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ github.com/docker/cli@v28.0.4+incompatible
  │ ✔✔ CVE-2025-15558         HIGH         8.0   EPSS:0.00020
  │        ↳ O:GHSA-p436-gjf2-799p,GO-2026-4610
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ github.com/docker/cli@v28.1.0+incompatible
  │ ✔✔ CVE-2025-15558         HIGH         8.0   EPSS:0.00020
  │        ↳ O:GHSA-p436-gjf2-799p,GO-2026-4610
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ github.com/docker/compose/v2@UNKNOWN
  │ ✔✘ CVE-2025-15558         HIGH         8.0   EPSS:0.00020
  │        ↳ O:GO-2026-4610
  │ ✔✘ CVE-2025-62725         HIGH         8.9   EPSS:0.00038
  │        ↳ O:GHSA-gv8h-7v7w-r22q,GO-2025-4077
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ github.com/docker/docker@v28.0.4+incompatible
  │ ✔✔ CVE-2026-33997         MEDIUM       6.8   EPSS:0.00011
  │        ↳ O:GHSA-pxq6-2prw-chj9,GO-2026-4883
  │ ✔✔ CVE-2026-34040         HIGH         8.8   EPSS:0.00012
  │        ↳ O:GHSA-x744-4wpc-v9h2,GO-2026-4887
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ github.com/docker/docker@v28.1.0+incompatible
  │ ✔✔ CVE-2026-33997         MEDIUM       6.8   EPSS:0.00011
  │        ↳ O:GHSA-pxq6-2prw-chj9,GO-2026-4883
  │ ✔✔ CVE-2026-34040         HIGH         8.8   EPSS:0.00012
  │        ↳ O:GHSA-x744-4wpc-v9h2,GO-2026-4887
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ github.com/go-viper/mapstructure/v2@v2.0.0
  │ ✔✔ CVE-2025-11065         MEDIUM       5.3   EPSS:0.00008
  │        ↳ O:GHSA-2464-8j7c-4cjm,GO-2025-3900
  │ ✔✔ GHSA-FV92-FJC5-JJ9H    MEDIUM       5.3                      n/a
  │        ↳ O:GO-2025-3787
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ github.com/moby/buildkit@v0.21.0
  │ ✔✔ CVE-2026-33747         CRITICAL     9.8   EPSS:0.00055
  │        ↳ O:GHSA-4c29-8rgm-jvjj,GO-2026-4858
  │ ✔✔ CVE-2026-33748         HIGH         8.2   EPSS:0.00022
  │        ↳ O:GHSA-4vrq-3vrq-g6gg,GO-2026-4859
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ go.opentelemetry.io/otel/sdk@v1.31.0
  │ ✔✔ CVE-2026-24051         HIGH         7.0   EPSS:0.00007
  │        ↳ O:GHSA-9h8m-3fm2-qjrq,GO-2026-4394
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ go.opentelemetry.io/otel/sdk@v1.34.0
  │ ✔✔ CVE-2026-24051         HIGH         7.0   EPSS:0.00007
  │        ↳ O:GHSA-9h8m-3fm2-qjrq,GO-2026-4394
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ golang.org/x/crypto@v0.37.0
  │ ✔✘ CVE-2025-47913         HIGH         7.5   EPSS:0.00039       1
  │        ↳ O:GO-2025-4116
  │ ✔✔ CVE-2025-47914         MEDIUM       5.3   EPSS:0.00021
  │        ↳ O:GHSA-f6x5-jh6r-wrfv,GO-2025-4135
  │ ✔✔ CVE-2025-58181         MEDIUM       5.3   EPSS:0.00087
  │        ↳ O:GHSA-j5w8-q4qc-rx2x,GO-2025-4134
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ golang.org/x/net@v0.39.0
  │ ✔✘ CVE-2025-47911         MEDIUM       5.3   EPSS:0.00013
  │        ↳ O:GO-2026-4440
  │ ✔✘ CVE-2025-58190         MEDIUM       5.3   EPSS:0.00015       1
  │        ↳ O:GO-2026-4441
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ golang.org/x/oauth2@v0.23.0
  │ ✔✔ CVE-2025-22868         HIGH         7.5   EPSS:0.00112
  │        ↳ O:GHSA-6v2p-p543-phr9,GO-2025-3488
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ golang.org/x/oauth2@v0.25.0
  │ ✔✔ CVE-2025-22868         HIGH         7.5   EPSS:0.00112
  │        ↳ O:GHSA-6v2p-p543-phr9,GO-2025-3488
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ google.golang.org/grpc@v1.69.4
  │ ✔✔ CVE-2026-33186         CRITICAL     9.1   EPSS:0.00014
  │        ↳ O:GHSA-p77j-4mvh-x3m3,GO-2026-4762
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ google.golang.org/grpc@v1.71.1
  │ ✔✔ CVE-2026-33186         CRITICAL     9.1   EPSS:0.00014
  │        ↳ O:GHSA-p77j-4mvh-x3m3,GO-2026-4762
  └────────────────────────────────────────────────────────────────────────────────
  ┌─ stdlib@go1.23.8
  │ ✘✔ CVE-2025-4674          HIGH         8.6   EPSS:0.00005
  │ ✘✔ CVE-2025-61731         HIGH         7.8   EPSS:0.00009
  │ ✘✔ CVE-2025-61732         HIGH         8.6   EPSS:0.00006
  │ ✔✘ CVE-2025-0913          MEDIUM       5.5   EPSS:0.00015
  │        ↳ O:GO-2025-3750
  │ ✔✔ CVE-2025-22873         LOW          3.8   EPSS:0.00004
  │        ↳ O:GO-2026-4403
  │ ✔✔ CVE-2025-4673          MEDIUM       6.8   EPSS:0.00021
  │        ↳ O:GO-2025-3751
  │ ✔✔ CVE-2025-47906         MEDIUM       6.5   EPSS:0.00028       1
  │        ↳ O:GO-2025-3956
  │ ✔✔ CVE-2025-47907         HIGH         7.0   EPSS:0.00012
  │        ↳ O:GO-2025-3849
  │ ✔✔ CVE-2025-47912         MEDIUM       5.3   EPSS:0.00022
  │        ↳ O:GO-2025-4010
  │ ✔✔ CVE-2025-58183         MEDIUM       4.3   EPSS:0.00012
  │        ↳ O:GO-2025-4014
  │ ✔✔ CVE-2025-58185         MEDIUM       5.3   EPSS:0.00023
  │        ↳ O:GO-2025-4011
  │ ✔✔ CVE-2025-58186         MEDIUM       5.3   EPSS:0.00028
  │        ↳ O:GO-2025-4012
  │ ✔✔ CVE-2025-58187         HIGH         7.5   EPSS:0.00013
  │        ↳ O:GO-2025-4007
  │ ✔✔ CVE-2025-58188         HIGH         7.5   EPSS:0.00006
  │        ↳ O:GO-2025-4013
  │ ✔✔ CVE-2025-58189         MEDIUM       5.3   EPSS:0.00009
  │        ↳ O:GO-2025-4008
  │ ✔✔ CVE-2025-61723         HIGH         7.5   EPSS:0.00027
  │        ↳ O:GO-2025-4009
  │ ✔✔ CVE-2025-61724         MEDIUM       5.3   EPSS:0.00016
  │        ↳ O:GO-2025-4015
  │ ✔✔ CVE-2025-61725         HIGH         7.5   EPSS:0.00028
  │        ↳ O:GO-2025-4006
  │ ✔✔ CVE-2025-61726         HIGH         7.5   EPSS:0.00032
  │        ↳ O:GO-2026-4341
  │ ✔✔ CVE-2025-61727         MEDIUM       6.5   EPSS:0.00011
  │        ↳ O:GO-2025-4175
  │ ✔✔ CVE-2025-61728         MEDIUM       6.5   EPSS:0.00022       1
  │        ↳ O:GO-2026-4342
  │ ✔✔ CVE-2025-61729         HIGH         7.5   EPSS:0.00022       2
  │        ↳ O:GO-2025-4155
  │ ✔✔ CVE-2025-61730         MEDIUM       5.3   EPSS:0.00008
  │        ↳ O:GO-2026-4340
  │ ✔✔ CVE-2025-68121         CRITICAL    10.0   EPSS:0.00017       1
  │        ↳ O:GO-2026-4337
  │ ✔✔ CVE-2026-25679         HIGH         7.5   EPSS:0.00031
  │        ↳ O:GO-2026-4601
  │ ✔✔ CVE-2026-27139         LOW          2.5   EPSS:0.00005
  │        ↳ O:GO-2026-4602
  │ ✔✔ CVE-2026-27142         MEDIUM       6.1   EPSS:0.00011
  │        ↳ O:GO-2026-4603
  └────────────────────────────────────────────────────────────────────────────────
