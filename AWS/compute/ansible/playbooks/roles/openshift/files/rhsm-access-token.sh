#!/usr/bin/env bash 

# Set the offline token value generated from https://access.redhat.com/management/api 
offline_token=$1

# Create a function to easily filter out JSON values:
function jsonValue() {
KEY=$1                                            
num=$2
awk -F"[,:}]" '{for(i=1;i<=NF;i++){if($i~/'$KEY'\042/){print $(i+1)}}}' | tr -d '"' | sed -n ${num}p
}

# Get the access token
curl https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/token -d grant_type=refresh_token -d client_id=rhsm-api -d refresh_token=$offline_token

# Grab the access token via jsonValue()
token=`curl https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/token -d grant_type=refresh_token -d client_id=rhsm-api -d refresh_token=$offline_token | jsonValue access_token`

# Perform API call
curl -H "Authorization: Bearer $token"  "https://api.access.redhat.com/management/v1/systems?limit=100" | jq