
#
# Playbooks are mostly meant for Openshift Container Platform management
#
# Instructions
# 1. Need to execute at the same directory level as roles
# 2. Ansible host must have ssh connectivity to remote host   
# 3. For playbooks running against AWS APIs you will to source your AWS credentials
#    * Linux host, export the following env variable
#        $ export AWS_SECRET_ACCESS_KEY=<secret access key>
#        $ export AWS_ACCESS_KEY_ID=<access key id>
#    * Windows host run 'aws configure' to set up or
#        C:\> set AWS_ACCESS_KEY_ID=<secret access key>
#        C:\> set AWS_SECRET_ACCESS_KEY=<access key id>
#        C:\> set AWS_DEFAULT_REGION=<aws region>
#     
####
