# Subnet role

This role is used to create new subnets.

tasks/main.yml: creation activities
    This section looping through the subnets dictionary defined in /newnetwork/hosts_vars/vpcname to create new subnets within vpc

meta/main.yml:
    Define the dependencies of subnet creation to vpc information and existence.  Subnet role will call vpc creation.  If vpc already exists,  set_facts will provide the vpc_id for subnet role play to continue

The role will create private subnets if vpc_private_subnets structure is defined
The role will create public subnets if vpc_public_subnets structure is defined AND public_facing=true
