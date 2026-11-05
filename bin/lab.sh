#!/usr/bin/env sh
# Starts the Dwarpal lab with one command. Free tools only: the JDK and Maven that the project already uses.
#
#   bin/lab.sh                 build the runnable jar if it is missing, then start the lab
#   bin/lab.sh --users 30      options are passed on (see docs/runbooks/lab.md)
#   bin/lab.sh --rebuild       build the jar again first
#
# Needs JDK 25 (JAVA_HOME or java on the PATH) and, for the first build, Maven.
set -eu
cd "$(dirname "$0")/.."
JAR=target/dwarpal-lab.jar
REBUILD=0
if [ "${1:-}" = "--rebuild" ]; then
  REBUILD=1
  shift
fi
[ -f "$JAR" ] || REBUILD=1
if [ "$REBUILD" = 1 ]; then
  echo "Building the lab jar..."
  mvn -q -Plab-jar -DskipTests -Djacoco.skip=true package
fi
if [ -n "${JAVA_HOME:-}" ]; then
  exec "$JAVA_HOME/bin/java" -jar "$JAR" "$@"
fi
exec java -jar "$JAR" "$@"
