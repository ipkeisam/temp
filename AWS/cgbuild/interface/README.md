# Release Pipeline Build Interface Scripts

## Summary
Build interface scripts and properties provide control over the CI build environment.  They must return a non-zero exit value if there is a failure

### Interface Scripts 
***
1.      `env.[sh|bat]`      Configure environment, called by other scripts
2.      `build.[sh|bat]`    Executes build, unit tests, and copies files to the artifacts folder
3.      `test.[sh|bat]`     Executes test cases, generate reports
4.      `analyze.[sh|bat]`  Executes code analysis and code coverage
5.      `package.[sh|bat]`  Package code
*in order of execution*


### Global Environment Variables
***
There are a number of global environmental variables that are present in the build environment at runtime.
* `CG_APP_NAME`             Application Name
* `CG_APP_VERSION`          Application Version
* `CG_BUILD_NUMBER`         Build Number
* `CG_BUILD_LABEL`          Source Control Label Name
* `CG_BUILD_TYPE`           Build Type (dev/rel)
* `CG_TOOLS_HOME`           Build Tools Home

*For a complete list, review the output of your bamboo build log*

For broader context and additional detail:
+ [Continuous Delivery Pipeline](https://confluence.capgroup.com/display/SLM/Continuous+Delivery+Pipeline)
+ [Build Interface Script and Property Standards](https://confluence.capgroup.com/display/CK/Build+Interface+Script+and+Property+Standards)