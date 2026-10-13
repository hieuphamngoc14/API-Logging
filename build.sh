#!/usr/bin/env bash
# Build without Gradle: compile, run the self-test, package dist/api-tracker.jar
set -euo pipefail
cd "$(dirname "$0")"
CP=libs/montoya-api-2026.7.jar:libs/sqlite-jdbc-3.53.4.0.jar
rm -rf build/classes build/test build/jar && mkdir -p build/classes build/test build/jar dist
javac --release 17 -encoding UTF-8 -Xlint:all,-serial,-processing -cp "$CP" -d build/classes $(find src/main/java -name '*.java')
javac --release 17 -encoding UTF-8 -cp "$CP:build/classes" -d build/test $(find src/test/java -name '*.java')
if [ "${SKIP_TESTS:-0}" != "1" ]; then
  java -Dstdout.encoding=UTF-8 -Dfile.encoding=UTF-8 -cp "$CP:build/classes:build/test" apitracker.SelfTest
fi
cp -r build/classes/. build/jar/
(cd build/jar && unzip -qo ../../libs/sqlite-jdbc-3.53.4.0.jar -x 'META-INF/MANIFEST.MF')
jar --create --file dist/api-tracker.jar -C build/jar .
ls -la dist/api-tracker.jar
# Integration test on a fake Burp (needs a display; on headless Linux use: IT=1 xvfb-run -a ./build.sh)
if [ "${IT:-0}" = "1" ]; then
  java -Dstdout.encoding=UTF-8 -Dfile.encoding=UTF-8 -cp "$CP:build/classes:build/test" apitracker.BurpIntegrationTest "${IT_SHOTS:-build}"
fi
