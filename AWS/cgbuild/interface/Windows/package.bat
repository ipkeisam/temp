@echo off
REM ------------------------------------------------------------------------
REM  Build automation interface script
REM ------------------------------------------------------------------------
set CG_BUILD_SCRIPT_NAME=package.bat
set BUILD_RC=0

echo ------------------------------------------------------------------------
echo Start Script: %CG_BUILD_SCRIPT_NAME%
echo ------------------------------------------------------------------------

REM ------------------------------------------------------------------------
REM  Environment specific settings should be read from env.bat
REM ------------------------------------------------------------------------
call env.bat

REM ------------------------------------------------------------------------
REM CD out of the cgbuild directory (.\cgbuild\interface\Windows) for
REM the rest of the relative paths within this script to work
REM ------------------------------------------------------------------------
cd ..\..\..

REM ------------------------------------------------------------------------
REM For CG NuGet libray packaging Only
REM
REM Setting the PACK_SUFFIX variable if build type is not release or master
REM ------------------------------------------------------------------------
REM set PACK_SUFFIX=
REM set BRANCH=
REM if "%bamboo_repository_branch_name%"=="develop" (
REM 	set PACK_SUFFIX=-suffix develop
REM 	set BRANCH=develop
REM )

REM if "%bamboo_repository_branch_name:~0,8%"=="feature/" (
REM 	set PACK_SUFFIX=-suffix feature
REM 	set BRANCH=feature
REM )

REM if "%bamboo_repository_branch_name:~0,8%"=="project/" (
REM 	set PACK_SUFFIX=-suffix project
REM 	set BRANCH=project
REM )


REM ------------------------------------------------------------------------
REM  Display parameters
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
echo Build Package ID           : %CG_BUILD_PKG_ID%
echo ------------------------------------------------------------------------


REM ------------------------------------------------------------------------
REM  Insert code below for packaging or for uploading internal packages 
REM  to the CG Nexus Repository such as CG Nuget or Maven.
REM ------------------------------------------------------------------------
if %bamboo_buildprops_package%==0 (
	echo --------------------------------------
	echo # SKIPPING RUNNING PACKAGE STEP
	echo ------------------------------------------------------------------------
	echo Finish script: %CG_BUILD_SCRIPT_NAME%
	echo ------------------------------------------------------------------------
	exit /B 0
)

if not exist cgbuild\dist\nul mkdir cgbuild\dist
if not exist cgbuild\dist\publish\nul mkdir cgbuild\dist\publish
if not exist cgbuild\dist\package\nul mkdir cgbuild\dist\package
REM xcopy your\package\*.* cgbuild\dist\publish /S /E
REM xcopy your\package\*.* cgbuild\dist\package /S /E
echo %CG_BUILD_PKG_ID% > cgbuild\dist\package\version.txt


REM ------------------------------------------------------------------------
REM  For Internal common libray packaging and uploading to the Nexus repository
REM  Insert code below.
REM ------------------------------------------------------------------------
REM "%MSBUILD_HOME%\MSBuild.exe" %BUILD_PATH%\nuget.msbuild /p:AppVersion=%FULL_VERSION%.0;Suffix="%PACK_SUFFIX%";Branch=%BRANCH%



if errorlevel 1 goto fail
goto end

:fail
set BUILD_RC=%ERRORLEVEL%
echo Build step failed
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
