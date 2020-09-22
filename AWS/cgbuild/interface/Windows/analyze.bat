@echo off
REM ------------------------------------------------------------------------
REM Reports automation interface script
REM ------------------------------------------------------------------------
set CG_BUILD_SCRIPT_NAME=analyze.bat
set BUILD_RC=0

echo ------------------------------------------------------------------------
echo Start Script: %CG_BUILD_SCRIPT_NAME%
echo ------------------------------------------------------------------------

REM ------------------------------------------------------------------------
REM Environment specific settings should be read from env.bat
REM ------------------------------------------------------------------------
call env.bat

REM ------------------------------------------------------------------------
REM CD out of the cgbuild directory (.\cgbuild\interface\Windows) for
REM the rest of the relative paths within this script to work
REM ------------------------------------------------------------------------
cd ..\..\..

REM ------------------------------------------------------------------------
REM Display parameters
REM ------------------------------------------------------------------------
echo ------------------------------------------------------------------------
echo Parameters Passed to Script: %CG_BUILD_SCRIPT_NAME%
echo ------------------------------------------------------------------------
echo Build Type                 : %CG_BUILD_TYPE%
echo Build Number               : %CG_BUILD_NUMBER%
echo Source Control Label Name  : %CG_BUILD_LABEL%
echo Source Control last change : %CG_SRC_LAST_CHANGE%
echo Application Name           : %CG_APP_NAME%
echo Application Version        : %CG_APP_VERSION%
echo Build Tools Home           : %CG_TOOLS_HOME%
echo NCover Project             : %CG_NCOVER_PROJECT_NAME%
echo Running Analyze Step       :
echo ------------------------------------------------------------------------

REM ------------------------------------------------------------------------
REM  Insert code below
REM ------------------------------------------------------------------------
set scheduled_flag=0
if "%CG_SCHEDULE_PLAN%"=="" set scheduled_flag=1
if "%CG_SCHEDULE_PLAN%" NEQ "1" set scheduled_flag=1
if "%scheduled_flag%"=="1" (
	if %bamboo_buildprops_analyze%==0 (
		echo --------------------------------------
		echo # Skipping Running Analyze Step
		echo ------------------------------------------------------------------------
		echo Finish script: %CG_BUILD_SCRIPT_NAME%
		echo ------------------------------------------------------------------------
		exit /B 0
	)
) else (
	echo Scheduled Run          
  	echo ------------------------------------------------------------------------
)

REM ----------------------------------------------------------------------------
REM SonarQube Analysis via Bamboo - Basic Usage Only
REM ----------------------------------------------------------------------------
REM To scan your source code and publish the results to SonarQube, simply execute
REM our Python script that is available on the build agents.
REM
REM usage: Python.exe sonar_scanner.py [-p=] [-v=] [-b=] [-d=] [(optional)-x=] [(optional)-l]
REM 
REM * The Python.exe is located at C:\Program Files\Python36
REM * sonar_scanner.py is located in a folder that is relative to BuildTools.  
REM * Version is the version you want to display in your SonarQube project. We
REM   recommend you use the App Version + Build Number (full app version).
REM * BaseDir is the base directory of the source code that you want to scan.
REM   Typically, the source code is in a folder at the same level as the CGBuild 
REM   folder that this analyze.bat is being executed from. 
REM NOTE: SonarQube 5.6.6 requires at least Java 8; JAVA_HOME needs to be set to 1.8
REM set JAVA_HOME=%CG_TOOLS_HOME%\c\win32\Sun\jdk\1.8.0_45

REM Change value if you prefer a different version
REM set version=%CG_APP_VERSION%.%CG_BUILD_NUMBER%

REM set baseDir=%bamboo_build_working_directory%..\..\..\source 

REM -------------------------------------------------------------------------
REM Boilerplate check of special branch value for scheduled analysis 
REM -------------------------------------------------------------------------
REM set branch=scheduled
REM if "%CG_SCHEDULE_PLAN%"=="" set branch=%bamboo_repository_branch_name%
REM -------------------------------------------------------------------------

REM Executing Code Analysis
REM set exclusions=lib/**/*,packages/**/*,*_Test/**/*
REM set scanner=C:\Program Files\Python36\python.exe %CG_TOOLS_HOME%\c\interface_scripts\analyze\sonar_scanner.py
REM %scanner% -p=YourProject -v=%version% -b=%branch% -d=%baseDir% -x=%exclusions%
REM optional arguments are:
REM -x=            Exclusions
REM -l             verbose logging

REM ------------------------------------------------------------------------
REM SonarQube Analysis via Bamboo - Only .NET projects with SonarQube Code Coverage
REM or Quality Profiles using Roslyn Rulesets 
REM ------------------------------------------------------------------------
REM Most of the work is done in the Build.bat and Test.bat. In order to send
REM analysis results to SonarQube server, just call the scanner wrapper with a 
REM single argument having the "end" value.
REM set scanner = C:\Program Files\Python36\python.exe %CG_TOOLS_HOME%\c\interface_scripts\analyze\sonar_scanner_msbuild.py
REM %scanner% -end

if %ERRORLEVEL% NEQ 0 goto fail
goto end

:fail
set BUILD_RC=%ERRORLEVEL%
echo Analyze step failed
echo ------------------------------------------------------------------------
echo Finish script: %CG_BUILD_SCRIPT_NAME%  Result: %BUILD_RC%
echo ------------------------------------------------------------------------
exit /B 1

:end
echo Build step completed
echo ------------------------------------------------------------------------
echo Finish script: %CG_BUILD_SCRIPT_NAME%  Result: %BUILD_RC%
echo ------------------------------------------------------------------------
exit /B 0