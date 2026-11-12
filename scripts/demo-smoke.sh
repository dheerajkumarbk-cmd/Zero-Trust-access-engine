#!/bin/bash
# One-command demo smoke test. Builds nothing: it starts a THROWAWAY lab from an already built jar, signs in as every
# demo account (dana, spector, cleo, ana, ben, hana), launches one scenario as an analyst and prints PASS/FAIL per step.
#
# Usage:   bash scripts/demo-smoke.sh <path-to-lab-jar> <port>
# Env:     DWARPAL_PW_DIR  (required) folder that contains node_modules/playwright-core
#                          e.g. C:/Users/Admin/AppData/Local/Temp/claude/550e57b10c013c0f/591614d6-a32a-4fd5-a922-1ea64941216b/scratchpad/pw
#          PW_CHANNEL      browser channel for Playwright (default: chrome)
#          JAVA            java executable (default: $JAVA_HOME/bin/java, else java on PATH)
# Needs:   Git Bash, curl, node, a Chrome install. Pick a free port; the lab keeps it until its own 300 s timeout ends.
# Safety:  the jar is copied to a fresh temp dir and the lab runs there (never a live lab); passwords and PINs are read
#          at run time from the throwaway lab's console/people.txt and are never printed. The lab is never killed.
# Exit:    0 when every step passes, 1 otherwise, 2 on bad usage.

JAR="$1"; PORT="$2"
if [ ! -f "$JAR" ] || ! [[ "$PORT" =~ ^[0-9]+$ ]]; then
  echo "usage: bash scripts/demo-smoke.sh <path-to-lab-jar> <port>"; exit 2
fi
if [ -z "$DWARPAL_PW_DIR" ] || [ ! -d "$DWARPAL_PW_DIR/node_modules/playwright-core" ]; then
  echo "FAIL setup - set DWARPAL_PW_DIR to a folder containing node_modules/playwright-core"; exit 2
fi
export PW_CHANNEL="${PW_CHANNEL:-chrome}"
if [ -z "$JAVA" ]; then
  if [ -n "$JAVA_HOME" ] && [ -x "$JAVA_HOME/bin/java" ]; then JAVA="$JAVA_HOME/bin/java"; else JAVA=java; fi
fi
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

TMP="$(mktemp -d)" || { echo "FAIL setup - mktemp"; exit 2; }
WTMP="$(cygpath -m "$TMP" 2>/dev/null || echo "$TMP")"   # Windows-style path for java and node
cp "$JAR" "$TMP/lab.jar" || { echo "FAIL setup - cannot copy the jar"; exit 2; }

timeout 300 "$JAVA" -jar "$WTMP/lab.jar" --dir "$WTMP/d" --port "$PORT" --db off --passkey typed --trail off \
  --users 20 --warmup-days 1 > "$TMP/lab.log" 2>&1 &

T0=$SECONDS; code=000
for _ in $(seq 1 60); do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://localhost:$PORT/" 2>/dev/null)
  [ "$code" = "200" ] && break
  sleep 2
done
START=$((SECONDS - T0))
if [ "$code" != "200" ]; then
  echo "FAIL lab start (${START}s) - last HTTP $code"; echo "SMOKE FAIL 1 of 1"; exit 1
fi
echo "PASS lab start (${START}s) - HTTPS GET / 200"

PEOPLE="$WTMP/d/console/people.txt"
if [ ! -f "$PEOPLE" ]; then echo "FAIL demo accounts - lab people file not found"; echo "SMOKE FAIL 1 of 2"; exit 1; fi

node "$HERE/demo-smoke.mjs" "$PORT" "$PEOPLE" "$WTMP/counts.txt" | cut -c1-240
read -r N F < "$TMP/counts.txt" 2>/dev/null || { N=1; F=1; echo "FAIL browser steps - helper did not finish"; }
N=$((N + 1))   # plus the lab-start step
if [ "$F" -eq 0 ]; then echo "SMOKE PASS $N/$N"; RC=0; else echo "SMOKE FAIL $F of $N"; RC=1; fi
echo "(lab ends by its own timeout; temp dir kept)"
exit $RC
