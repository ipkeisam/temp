#!/bin/ksh

# ------------------------------------------------------------------------
# Build automation interface script
# ------------------------------------------------------------------------
CG_BUILD_SCRIPT_NAME=build.sh
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
echo Running Build Step         :
echo ------------------------------------------------------------------------

# ------------------------------------------------------------------------
#  Insert code below
# ------------------------------------------------------------------------

# ------------------------------------------------------------------------
# Create directories as needed
# ------------------------------------------------------------------------

[ -d ./cgbuild/dist ] && rm -rf ./cgbuild/dist
[ ! -d ./cgbuild/dist/package ] && mkdir -p ./cgbuild/dist/package
[ ! -d ./cgbuild/dist/publish/artifacts ] && mkdir -p ./cgbuild/dist/publish/artifacts
[ ! -d ./cgbuild/dist/publish/package ] && mkdir -p ./cgbuild/dist/publish/package

# ------------------------------------------------------------------------
# Build the solution
# ------------------------------------------------------------------------
# CG_BUILD_TYPE set within ./cgbuild/property/dev.properties (<branchname>.build.type)
BUILD_RC=0

# Setting the Maven Build Version
RELEASE_VERSION=""
if [[ ${bamboo_planRepository_branch} == *"release"* ]] 
then
  RELEASE_VERSION="-Drevision=${CG_APP_VERSION}.${CG_BUILD_NUMBER}"
fi

# ----------------------------------------------
# Maven Build Command for Producer Project
# ----------------------------------------------
#echo "Release Version: ${RELEASE_VERSION}"
#echo "Running: ${M3_HOME}/bin/mvn clean install ${RELEASE_VERSION}"
#${M3_HOME}/bin/mvn clean install ${RELEASE_VERSION}

# ----------------------------------------------
# Maven Build Command for Standard Project
# ----------------------------------------------
#export project_root=`pwd`
#MVN_SETTINGS=${project_root}/cgbuild/interface/UNIX/mvn_settings.xml
#${M3_HOME}/bin/mvn -s ${MVN_SETTINGS} -Drelease.version=${RELEASE_VERSION} -Dbuild.type=debug install

# ----------------------------------------------
# Python Build Command for Project with external packages
# ----------------------------------------------
# BUILD_UTIL=${CG_TOOLS_HOME}/c/interface_scripts/buildutil
# export BUILD_UTIL
# /users/python/python36/bin/python ${BUILD_UTIL}/pythonwheel/wheel_install.py ./<SOME_FOLDER>/requirements.txt


# Set the system status code
# BUILD_RC=$?

if [ ${CG_BUILD_TYPE} == 'rel' ]
then
  echo Build Type is ${CG_BUILD_TYPE}
  # build with release flags
  # BUILD_RC=$?
fi

if [ ${CG_BUILD_TYPE} == 'dev' ]
then
  echo Build Type is ${CG_BUILD_TYPE}
  # build with debug flags
  # BUILD_RC=$?
fi


# ------------------------------------------------------------------------
# Copy the needed artifacts from the build and publish them
# ------------------------------------------------------------------------
if [ ${CG_BUILD_TYPE} == 'rel' ]
then
    echo Copy release artifacts
    # copy release build binaries to cgbuild/dist/package
fi

if [ ${CG_BUILD_TYPE} == 'dev' ]
then
    echo Copy release artifacts
    # copy debug build binaries to cgbuild/dist/package
fi


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