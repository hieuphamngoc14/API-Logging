# Build without Gradle on Windows (needs JDK 17+ on PATH): compile, run the self-test, package dist\api-tracker.jar
# Run:   powershell -ExecutionPolicy Bypass -File .\build.ps1
#        $env:SKIP_TESTS=1; .\build.ps1      (skip the self-test)
#        $env:IT=1; .\build.ps1              (also run the integration test on a fake Burp, opens a Swing window)
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$cp = "libs\montoya-api-2026.7.jar;libs\sqlite-jdbc-3.53.4.0.jar"
Remove-Item -Recurse -Force build\classes, build\test, build\jar -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force build\classes, build\test, build\jar, dist | Out-Null

$main = Get-ChildItem -Recurse src\main\java -Filter *.java | ForEach-Object { $_.FullName }
$test = Get-ChildItem -Recurse src\test\java -Filter *.java | ForEach-Object { $_.FullName }
javac --release 17 -encoding UTF-8 -Xlint:all,-serial,-processing -cp $cp -d build\classes $main
if ($LASTEXITCODE -ne 0) { throw "javac (main) failed" }
javac --release 17 -encoding UTF-8 -cp "$cp;build\classes" -d build\test $test
if ($LASTEXITCODE -ne 0) { throw "javac (test) failed" }

if ($env:SKIP_TESTS -ne "1") {
    java "-Dstdout.encoding=UTF-8" "-Dfile.encoding=UTF-8" -cp "$cp;build\classes;build\test" apitracker.SelfTest
    if ($LASTEXITCODE -ne 0) { throw "self-test failed" }
}
if ($env:IT -eq "1") {
    java "-Dstdout.encoding=UTF-8" "-Dfile.encoding=UTF-8" -cp "$cp;build\classes;build\test" apitracker.BurpIntegrationTest build
    if ($LASTEXITCODE -ne 0) { throw "integration test failed" }
}

Copy-Item -Recurse build\classes\* build\jar\
Push-Location build\jar
jar xf ..\..\libs\sqlite-jdbc-3.53.4.0.jar
Remove-Item -Force META-INF\MANIFEST.MF -ErrorAction SilentlyContinue
Pop-Location
jar --create --file dist\api-tracker.jar -C build\jar .
Get-Item dist\api-tracker.jar
