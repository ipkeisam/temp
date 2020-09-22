#!/bin/ksh

# ------------------------------------------------------------------------
# Build automation interface script
# ------------------------------------------------------------------------
CG_BUILD_SCRIPT_NAME=test.sh
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
echo ------------------------------------------------------------------------


# ------------------------------------------------------------------------
#  Insert code below
# ------------------------------------------------------------------------

if [ ${bamboo_buildprops_test} -eq 0 ]
then
  if [ ${bamboo_buildprops_parse_junit} -eq 0 ] || [ ${bamboo_buildprops_parse_mstest} -eq 0 ] || [ ${bamboo_buildprops_parse_nunit} -eq 0 ]
  then
    # To skip test execution, the parsers and test property must both be disabled [0] in dev.properties
    echo ------------------------------------------------------------------------
    echo Skipping Running Test Step
    echo ------------------------------------------------------------------------
    echo Finish script: ${CG_BUILD_SCRIPT_NAME}
    echo ------------------------------------------------------------------------
    exit 0
  fi
fi

echo "Running Test Step Commands"
BUILD_RC=0

# ------------------------------------------------------------------------
#  Remove comment from below code to generate PMD Reports
# ------------------------------------------------------------------------

#  Insert below code for PMD Reports using Maven 3.0.5
#${M3_HOME}/bin/mvn pmd:pmd

#  Insert below code for PMD Reports using ANT 1.8.2
#${ANT_HOME}/bin/ant -v -Dpmd.lib=${PMD_LIB} -f example_build_PMD.xml pmd

# ------------------------------------------------------------------------
#  Remove comment from below code to generate Clover Reports
# ------------------------------------------------------------------------

# Insert below code for Clover Reports using Maven 3.0.5
#${M3_HOME}/bin/mvn -Dclover.lic=${CLOVER_PATH} clover2:setup test clover2:aggregate clover2:clover

#  Insert below code for Clover Reports using ANT 1.8.2
#  Below mentioned example shows the best practice to create clover report after clean, compile, run junit test on build
#${ANT_HOME}/bin/ant -Dclover.path=${CLOVER_PATH} -f example_build_Clover.xml with.clover clean-build compile junit clover.report

# ------------------------------------------------------------------------
#  Remove comment from below code to generate Python Reports using PyTest w/ JUNIT Format
# ------------------------------------------------------------------------
# Don't create the virtual environment again if you already executed wheel_install.py
# /users/python/python36/bin/python -m venv python

# CD into the base directory of the source code
# cd <src>

# ./python/bin/python -m pytest ./<path to tests> --junitxml=../${JUNIT_RESULTS_PATH}/results.xml


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
