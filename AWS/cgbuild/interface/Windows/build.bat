@echo off
REM ------------------------------------------------------------------------
REM Build automation interface script
REM ------------------------------------------------------------------------
set CG_BUILD_SCRIPT_NAME=build.bat
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
echo Running Build Step         :
echo ------------------------------------------------------------------------

REM ------------------------------------------------------------------------
REM  Insert build and unit test code below
REM ------------------------------------------------------------------------

REM ------------------------------------------------------------------------
REM Create directories as needed
REM ------------------------------------------------------------------------

if exist cgbuild\dist\nul rmdir cgbuild\dist /S /Q
if not exist cgbuild\dist\nul mkdir cgbuild\dist
if not exist cgbuild\dist\package\nul mkdir cgbuild\dist\package
if not exist cgbuild\dist\publish\artifacts\nul mkdir cgbuild\dist\publish\artifacts
if not exist cgbuild\dist\publish\package\nul mkdir cgbuild\dist\publish\package

REM ------------------------------------------------------------------------
REM Build the solution
REM ------------------------------------------------------------------------
REM CG_BUILD_TYPE set within ./cgbuild/property/dev.properties (<branchname>.build.type)

REM ----------------------------------------------------------------------------
REM SonarQube Analysis via Bamboo - Only .NET projects with SonarQube Code Coverage
REM or Quality Profiles using Roslyn Rulesets 
REM ----------------------------------------------------------------------------
REM Call wrapper scanner to begin pre-processing step for build, test, and analyzing the code using sonar-scanner-msbuild.exe for C# Code Coverage Analysis 
REM with SonarQube. This is only required for .NET components that wants code coverage reported to SonarQube or if the project in SonaQube has Quality Profiles
REM with "Roslyn" rulesets. If none of this makes sense then you probably don't need it.
REM -------------------------------------------------------------------------
REM python.exe sonar_scanner_msbuild.py [-begin] [-p=] [-v=] [-b=] [-d=] [-t=vscoveragexml|dotcover|opencover|ncover3] [-r=] [(optional)-x=] [(optional)-l]
REM -------------------------------------------------------------------------

REM -------------------------------------------------------------------------
REM Boilerplate check of special branch value for scheduled analysis 
REM -------------------------------------------------------------------------
REM set branch=scheduled
REM if "%CG_SCHEDULE_PLAN%"=="" set branch=%bamboo_repository_branch_name%
REM -------------------------------------------------------------------------

REM Note: FULL_VERSION, BASE_DIR, and XUNIT_RESULTS_PATH environment variables need to be defined in Env.bat or here.
REM Exclusion of files or projects that is not desired for code analysis
REM set exclusions = ""
REM set scanner="%CG_TOOLS_HOME%\..\synced_repos\interface_scripts\analyze\sonar_scanner_msbuild.py"
REM "C:\Program Files\Python36\python.exe" %scanner% -begin -p=YourComponent -v=%FULL_VERSION% -b=%branch% -d=%BASE_DIR% -t=dotcover -r=%XUNIT_RESULTS_PATH%\dotCover.html -x=exclusions
REM if %ERRORLEVEL% NEQ 0 goto fail
REM ----------------------------------------------------------------------------

REM Build the solution 
REM %MSBUILD_HOME%\MSBuild.exe Test_App/Test_App.sln /p:Configuration=Release /t:Rebuild
REM if %ERRORLEVEL% NEQ 0 goto fail

REM Example NuGet Build
REM ----------------------------------------------------------------------------
REM Getting 3rd Party NuGet Libraries first
REM "%MSBUILD_HOME%\MSBuild.exe" %BUILD_PATH%\import.msbuild
REM if %ERRORLEVEL% NEQ 0 goto fail

REM Building the Application
REM "%MSBUILD_HOME%\MSBuild.exe" %BUILD_PATH%\build.msbuild /p:AppVersion=%FULL_VERSION%.0;BuildPackageId=%CG_BUILD_PKG_ID%
REM if %ERRORLEVEL% NEQ 0 goto fail
REM ----------------------------------------------------------------------------

REM Example Maven Build
REM call "%M3_HOME%\bin\mvn.bat" -Drelease.version=%CG_APP_VERSION% package < package/assembly:directory >
REM if %ERRORLEVEL% NEQ 0 goto fail

REM Example Python Build with external packages
REM set BUILD_UTIL=%CG_TOOLS_HOME%\c\interface_scripts\buildutil
REM C:\Program Files\Python36\python.exe %BUILD_UTIL%\pythonwheel\wheel_install.py <SOME_FOLDER>\requirements.txt
REM if %ERRORLEVEL% NEQ 0 goto fail

REM Make use of CG_BUILD_TYPE to optionally control build/test flags.  Build type will always be 'dev' unless
REM building on a release branch within GIT

REM Execute seperate test execution (if desired), optionally fail
REM if %ERRORLEVEL% NEQ 0 goto test_failure

if %CG_BUILD_TYPE%=="rel" (
    REM build with release flags
)

if %CG_BUILD_TYPE%=="dev" (
    REM build with debug flags
)

REM ------------------------------------------------------------------------
REM Copy the needed artifacts from the build and publish them
REM ------------------------------------------------------------------------
if %CG_BUILD_TYPE%=="rel" (
    REM xcopy TestProject\bin\Release\*.dll cgbuild\dist\package
    REM xcopy TestNCover\bin\Release\*.* cgbuild\dist\publish\artifacts
)

if %CG_BUILD_TYPE%=="dev" (
    REM xcopy TestProject\bin\Debug\*.dll cgbuild\dist\package
    REM xcopy TestNCover\bin\Debug\*.* cgbuild\dist\publish\artifacts
)

if %ERRORLEVEL% NEQ 0 goto fail
goto end

:fail
set BUILD_RC=%ERRORLEVEL%
echo Build step failed
echo ------------------------------------------------------------------------
echo Finish script: %CG_BUILD_SCRIPT_NAME%  Result: %BUILD_RC%
echo ------------------------------------------------------------------------
exit /B 1

:test_failure
set BUILD_RC=%ERRORLEVEL%
echo One or more tests have failed for this build.
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