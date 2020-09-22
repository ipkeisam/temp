#!/usr/bin/env bash

create_userWithGroupMembership() {
    params=$1
    counter=0
    userAccounts=()
    primaryGroup=()
    secondaryGroups=()
    for val in ${params[*]}
    do
        counter=$((counter + 1))
        if [ $counter -eq 1 ]; then
            userAccounts=$val
        fi
        if [ $counter -eq 2 ]; then
            primaryGroup=$val
        fi
        if [ $counter -eq 3 ]; then
            secondaryGroups=$val
        fi
    done


    userAccounts=`echo $userAccounts | tr ',' ' '`
    for acct in ${userAccounts[*]}
        do
            useradd $acct 2> /dev/null
    	    rc=$?
    	    if [ $returnCode -eq 0 ];  then echo account $acct created
    	    fi
    	    if [ $returnCode -eq 9 ];  then echo account $acct already exists
	    fi

	    if [ $primaryGroup != "-" ];  then
	    	usermod -g $primaryGroup $acct 2> /dev/null
	    	rc=$?
	    	echo $rc
    	    	if [ $rc -eq 0 ];  then echo account:$acct added to primary group:$primaryGroup
    	    	fi
	    fi

	    if [ $secondaryGroups != "-" ];  then
	        # -a not added to the command
	    	usermod -G $secondaryGroups $acct 2> /dev/null
	    	rc=$?
	    	echo $rc
    	    	if [ $rc -eq 0 ];  then echo account:$acct added to secondary groups:$secondaryGroups
    	    	fi
	    fi
	done

    return 0
}

userinfo=( "chpp,cuot,sxm" "-" "afwggrp,digitaladmin" )

create_userWithGroupMembership "${userinfo[*]}"

echo All Done.