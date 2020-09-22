#!/bin/ksh

# ------------------------------------------------------------------------
# Build automation interface script
# ------------------------------------------------------------------------
CG_BUILD_SCRIPT_NAME=package.sh
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
echo Source Control Server      : ${CG_SRC_SERVER}
echo Source Control Client View : ${CG_SRC_SPEC}
echo Source Control last change : ${CG_SRC_LAST_CHANGE}
echo Application Name           : ${CG_APP_NAME}
echo Application Version        : ${CG_APP_VERSION}
echo Build Tools Home           : ${CG_TOOLS_HOME}
echo Build Package ID           : ${CG_BUILD_PKG_ID}
echo ------------------------------------------------------------------------


# ------------------------------------------------------------------------
#  Insert code below
# ------------------------------------------------------------------------
if [ ${bamboo_buildprops_package} -eq 0 ]
then
    echo Skipping Running Package Step
    exit 0
fi

echo "Running Build Step Commands"
BUILD_RC=0
mkdir -p ./cgbuild/dist/package
echo ${CG_BUILD_PKG_ID} > cgbuild/dist/package/version.txt

# ----------------------------------------------
# Maven Package Command for Producer Project
# ----------------------------------------------
# Setting the Maven Build Version
RELEASE_VERSION=""
if [[ ${bamboo_planRepository_branch} == *"release"* ]]
then
  RELEASE_VERSION="-Drevision=${CG_APP_VERSION}.${CG_BUILD_NUMBER}"
fi
# Run Maven to upload the artifacts
#echo "Release Version: ${RELEASE_VERSION}"
#echo "Running: ${M3_HOME}/bin/mvn deploy ${RELEASE_VERSION}"
#${M3_HOME}/bin/mvn deploy ${RELEASE_VERSION}

# Set the system status code
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
