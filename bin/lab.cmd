@echo off
rem Starts the Dwarpal lab with one command. Free tools only: the JDK and Maven that the project already uses.
rem
rem   bin\lab.cmd                 build the runnable jar if it is missing, then start the lab
rem   bin\lab.cmd --users 30      options are passed on (see docs/runbooks/lab.md)
rem   bin\lab.cmd --rebuild       build the jar again first
rem
rem Needs JDK 25 (JAVA_HOME or java on the PATH) and, for the first build, Maven.
setlocal
cd /d "%~dp0.."
set JAR=target\dwarpal-lab.jar
set REBUILD=0
if "%1"=="--rebuild" (
  set REBUILD=1
  shift
)
if not exist "%JAR%" set REBUILD=1
if "%REBUILD%"=="1" (
  echo Building the lab jar...
  call mvn -q -Plab-jar -DskipTests -Djacoco.skip=true package
  if errorlevel 1 (
    echo The build failed. See the messages above.
    exit /b 1
  )
)
if defined JAVA_HOME (
  "%JAVA_HOME%\bin\java" -jar "%JAR%" %*
) else (
  java -jar "%JAR%" %*
)
endlocal
