@echo off
REM ------------------------------------------------------------------------
REM Reports automation interface script
REM ------------------------------------------------------------------------
set CG_BUILD_SCRIPT_NAME=test.bat
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
echo Source Control Server      : %CG_SRC_SERVER%
echo Source Control Client View : %CG_SRC_SPEC%
echo Source Control last change : %CG_SRC_LAST_CHANGE%
echo Application Name           : %CG_APP_NAME%
echo Application Version        : %CG_APP_VERSION%
echo Build Tools Home           : %CG_TOOLS_HOME%
echo NCover Project             : %CG_NCOVER_PROJECT_NAME%
echo ------------------------------------------------------------------------

REM ------------------------------------------------------------------------
REM  Insert code below
REM ------------------------------------------------------------------------

if %bamboo_buildprops_test%==0 (
    if %bamboo_buildprops_parse_junit%==0  set skip=true
    if %bamboo_buildprops_parse_mstest%==0 set skip=true
    if %bamboo_buildprops_parse_nunit%==0  set skip=true
    if "%skip%"=="true" (
        REM To skip test execution, the parsers and test property must both be disabled [0] in dev.properties
        echo --------------------------------------
        echo # Skipping Running Test Step
        echo ------------------------------------------------------------------------
        echo Finish script: %CG_BUILD_SCRIPT_NAME%
        echo ------------------------------------------------------------------------
        exit /B 0
    )
)

REM ---------------------------------------------------------------------
REM  Insert code below to generate PMD Reports using Maven/ANT
REM ---------------------------------------------------------------------


REM  Remove comment to generate PMD Reports using Maven build
REM call "%M3_HOME%\bin\mvn.bat" pmd:pmd

REM  Remove comment to generate PMD Reports using ANT build
REM call "%ANT_HOME%\bin\ant.bat" -v -Dpmd.lib=%PMD_LIB% -f example_build_PMD.xml pmd



REM ---------------------------------------------------------------------
REM  Insert code to below generate Clover Reports using Maven/ANT
REM ---------------------------------------------------------------------


REM  Remove comment from below command to generate Clover Reports using Maven build
REM call "%M3_HOME%\bin\mvn.bat" -Dclover.lic=%CLOVER_PATH% clover2:setup test clover2:aggregate clover2:clover

REM  Remove comment from below command to generate Clover Reports using ANT build
REM  Below mentioned example shows the best practice to create clover report after clean, compile, run junit test on build
REM call "%ANT_HOME%\bin\ant.bat" -Dclover.path=%CLOVER_PATH% -f example_build_clover.xml with.clover clean-build compile junit clover.report



REM --------------------------------------------------------------------------------------------------
REM  Insert code to generate NCover Reports; Example given below to create NCover Reports using MSTest
REM --------------------------------------------------------------------------------------------------


REM Create driectories as needed
REM Note: NCover environment/project name defined in env.bat for this example
REM if not exist cgbuild\dist\reports\NCover\nul mkdir cgbuild\dist\reports\NCover

REM Create code coverage results from NCover and publish NCover reports
REM %NCOVER_HOME%\NCover sync-disable --project=Test_NCover_MSTest
REM %NCOVER_HOME%\NCover Run --project=%CG_NCOVER_PROJECT_NAME% --buildId=%CG_BUILD_NUMBER% -- "%MSTEST_HOME%\MSTest.exe" /testcontainer:cgbuild\dist\package\TestProject.dll
REM %NCOVER_HOME%\NCover Export --project=%CG_NCOVER_PROJECT_NAME% --include --file="cgbuild\dist\reports\NCover\coverage-report.xml" --format=v3xml

REM %NCOVER_HOME%\NCover sync-enable --project=%CG_NCOVER_PROJECT_NAME%

REM --------------------------------------------------------------------------------------------------
REM  Insert code to generate MSTest Reports
REM --------------------------------------------------------------------------------------------------
REM if not exist cgbuild\dist\reports\MSTest\nul mkdir cgbuild\dist\reports\MSTest
REM xcopy TestReports\mstest\*.trx cgbuild\dist\reports\MSTest /S /E


REM --------------------------------------------------------------------------------------------------
REM Insert code to generate Unit Test and Code Coverage Reports (dotCover and XUnit example)
REM Needed for uploading .NET code coverage to SonarQube
REM --------------------------------------------------------------------------------------------------
REM Create report directory.
REM if not exist %XUNIT_RESULTS_PATH%\nul mkdir %XUNIT_RESULTS_PATH%

REM list of test binaries
REM set "list=%BUILD_PATH%..\..\App1_Test.dll %BUILD_PATH%..\..\App2_Test.dll"

REM BASE_DIR environment variable is set in Env.bat
REM Both dotCover and XUnit are NuGet packages need to be in the CG NuGet Repo
REM Output HTML filename need to match the one set in the pre-processing step
REM "%BASE_DIR%\packages\JetBrains.dotCover.CommandLineTools.2016.3.20161223.160402\tools\dotCover.exe" analyse /ReportType=HTML /Output="%XUNIT_RESULTS_PATH%\dotCover.html" /TargetExecutable="%XUNIT_HOME%\xunit.console.exe" /TargetWorkingDir="%BASE_DIR%" /TargetArguments="%list% -nunit .\%XUNIT_RESULTS_PATH%\Tests.xml -verbose"



REM -----------------------------------------------------------------------------
REM  Insert code to below generate PYTHON Reports using PyTest w/ JUNIT Format
REM -----------------------------------------------------------------------------
REM Don't create the virtual environment again if you already executed wheel_install.py
REM C:\Program Files\Python36\python.exe -m venv python

REM CD into the base directory of the source code
REM cd <src>

REM Use the python.exe in the path of the virtual environment instead of activating and deactivating.
REM python\Scripts\python.exe -m pytest <path to tests> --junitxml=..\%JUNIT_RESULTS_PATH%\results.xml


if %ERRORLEVEL% NEQ 0 goto fail
goto end

:end
echo Build step completed
echo ------------------------------------------------------------------------
echo Finish script: %CG_BUILD_SCRIPT_NAME%  Result: %BUILD_RC%
echo ------------------------------------------------------------------------
exit /B 0
