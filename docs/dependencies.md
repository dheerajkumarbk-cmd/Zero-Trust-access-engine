# Dependencies

Dwarpal is written to need as little as possible. Everything not listed here comes from the JDK itself (the web server,
TLS, cryptography including AES-GCM and the WebAuthn signature checks, JSON handling for the console, and HTTP for the
tests). Nothing here costs money.

## Runtime (inside the lab jar)

| Dependency | Version | Licence | Why |
|---|---|---|---|
| PostgreSQL JDBC driver (`org.postgresql:postgresql`, pgjdbc) | 42.7.14 | BSD-2-Clause | The only way the lab talks to the directory database. Only the `dev.dwarpal.directory` package uses it (`DirectorySourceTest.onlyTheDirectoryPackageTouchesJdbc`). Its optional annotation library `checker-qual` is excluded because it holds annotations the driver does not need at run time. |
| SnakeYAML (`org.yaml:snakeyaml`) | 2.7 | Apache-2.0 | Reads policy files. Always loaded with `SafeConstructor` (see `SafePolicyLoader`), so a policy file cannot construct arbitrary objects. |

## Run-time services

| Service | Version tested | Licence | Why |
|---|---|---|---|
| PostgreSQL server | 18.6 | PostgreSQL Licence (BSD-style) | The directory database. Set up in [setup.md](setup.md). |

## Build and test only (not in the lab jar)

| Tool | Version | Licence | Why |
|---|---|---|---|
| JDK | 25 (Eclipse Temurin) | GPL-2.0 with Classpath Exception | Compiler and runtime. |
| Maven | 3.9 or newer | Apache-2.0 | Build. |
| JUnit Jupiter | 5.14.4 | EPL-2.0 | Tests. |
| JaCoCo | 0.8.16 | EPL-2.0 | Coverage gate, at least 80 percent. |
| SpotBugs Maven plugin | 4.10.5.0 | LGPL-2.1 | Static analysis; must report zero findings. |
| Find Security Bugs | 1.14.0 | LGPL-3.0 | Security rules for SpotBugs. |
| CycloneDX Maven plugin | 2.9.3 | Apache-2.0 | Writes the software bill of materials (`target/bom.json`). |
| Maven Shade plugin | 3.5.3 | Apache-2.0 | Builds the one-jar lab (profile `lab-jar`). |
| Node.js (optional) | any current | MIT | Only `ConsoleScriptsParseTest`, which checks that every console script parses. Skipped when Node is absent. |

## In the browser console (no network, no CDN)

| Item | Licence |
|---|---|
| Libre Baskerville, Almarai and JetBrains Mono fonts, served from `console/fonts` | SIL Open Font Licence (text in `fonts/LICENSE.txt`) |
| Natural Earth land shapes for the sign-in globe | Public domain |

The console loads nothing from any other server; its content-security policy forbids it, and `ConsoleSourceTest` fails the
build if a script names an outside address. There is no JavaScript framework: the front end is plain ES modules.

## Not used

LDAP, MongoDB and H2 were considered and not built. See [iam-architecture.md](iam-architecture.md), "Known limitations".
