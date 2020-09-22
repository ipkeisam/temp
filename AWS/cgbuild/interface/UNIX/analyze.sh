#!/bin/ksh

# ------------------------------------------------------------------------
# Reports automation interface script
# ------------------------------------------------------------------------

CG_BUILD_SCRIPT_NAME=analyze.sh
BUILD_RC=0

echo ------------------------------------------------------------------------
echo Start Script: ${CG_BUILD_SCRIPT_NAME}
echo ------------------------------------------------------------------------

# ------------------------------------------------------------------------
# Environment specific settings should be read from env.sh
# ------------------------------------------------------------------------
. ./env.sh

# ------------------------------------------------------------------------
# CD out of the cgbuild directory (./cgbuild/interface/UNIX) for
# the rest of the relative paths within this script to work
# ------------------------------------------------------------------------
cd ../../..

# ------------------------------------------------------------------------
# Display parameters
# ------------------------------------------------------------------------
echo ------------------------------------------------------------------------
echo Parameters Passed to Script: ${CG_BUILD_SCRIPT_NAME}
echo ------------------------------------------------------------------------
echo Build Type                 : ${CG_BUILD_TYPE}
echo Build Number               : ${CG_BUILD_NUMBER}
echo Source Control Label Name  : ${CG_BUILD_LABEL}
echo Source Control last change : ${CG_SRC_LAST_CHANGE}
echo Application Name           : ${CG_APP_NAME}
echo Application Version        : ${CG_APP_VERSION}
echo Build Tools Home           : ${CG_TOOLS_HOME}
echo Running Analyze Step       :
echo ------------------------------------------------------------------------

# ------------------------------------------------------------------------
#  Insert code below
# ------------------------------------------------------------------------
if [[ -z "${CG_SCHEDULE_PLAN}" || ${CG_SCHEDULE_PLAN} -ne 1 ]] 
then
  if [ ${bamboo_buildprops_analyze} -eq 0 ]
  then
      echo ------------------------------------------------------------------------
      echo Skipping Running Analyze Step
      echo ------------------------------------------------------------------------
      echo Finish script: ${CG_BUILD_SCRIPT_NAME}
      echo ------------------------------------------------------------------------
      exit 0
  fi
else
  echo Scheduled Run          
  echo ------------------------------------------------------------------------
fi

# ----------------------------------------------------------------------------
# SonarQube Analysis via Bamboo
# ----------------------------------------------------------------------------
# To scan your source code and publish the results to SonarQube, simply execute
# our Python script that is available on the build agents.
#
# -------------------------------------------------------------------------
# usage: python sonar_scanner.py [-p=] [-v=] [-b=] [-d=] [(optional)-x=] [(optional)-l]
# -------------------------------------------------------------------------
# 
# * The Python is located in a sub folder in /users/python/python36/bin
# * sonar_scanner.py is located in a folder that is relative to BuildTools.  
# * Version is the version you want to display in your SonarQube project. We
#   recommend you use the App Version + Build Number (full app version).
# * BaseDir is the base directory of the source code that you want to scan.
#   Typically, the source code is in a folder at the same level as the CGBuild 
#   folder that this analyze.bat is being executed from. 
#
# NOTE: SonarQube 5.6.6 requires at least Java 8; JAVA_HOME needs to be set to 1.8

# JAVA_HOME=${CG_TOOLS_HOME}/c/linux/Sun/jdk/1.8.0_45
# export JAVA_HOME

# Change value if you prefer a different version
# version=${CG_APP_VERSION}.${CG_BUILD_NUMBER}

# baseDir=${bamboo_build_working_directory}/src

# Executing Code Analysis
# -------------------------------------------------------------------------
# Boilerplate check of special branch value for scheduled analysis 
# -------------------------------------------------------------------------
# branch=scheduled
# if [[ -z "${CG_SCHEDULE_PLAN}" ]]
# then 
#   branch=${bamboo_repository_branch_name}
# fi 
# -------------------------------------------------------------------------

# exclusions=
# scanner="/users/python/python36/bin/python ${CG_TOOLS_HOME}/c/interface_scripts/analyze/sonar_scanner.py"
# ${scanner} -p=YourProject -v=${version} -b=${branch} -d=${baseDir} -x=${exclusions}
# optional arguments are:
# -x=            Exclusions
# -l             verbose logging

BUILD_RC=$?

if [ ${BUILD_RC} -ne 0 ]
then
  echo Build step failed
  echo ------------------------------------------------------------------------
  echo Finish script: ${CG_BUILD_SCRIPT_NAME}  Result: ${BUILD_RC}
  echo ------------------------------------------------------------------------
  exit 1
fi


echo Build step completed
echo ------------------------------------------------------------------------
echo Finish script: ${CG_BUILD_SCRIPT_NAME}  Result: ${BUILD_RC}
echo ------------------------------------------------------------------------

exit $?