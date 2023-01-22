#!/bin/bash

#Variable Descriptions:
#   1) SPECIFIC_ACCOUNTID_LIST (SPACE DELIMITED): List specific accounts if you wish to run the command only against those
#        or leave "allaccounts" to detect and execute against all accounts in the AWS Org
#   2) REGION_LIST (SPACE DELIMITED): Specify regions to analyze with Network Access Analyzer
#   3) IAM_CROSS_ACCOUNT_ROLE: The IAM Role name created for cross account execution
#   4) SCRIPT_EXECUTION_MODE:
#       Specify CREATE_ANALYZE to direct the script to create Network Access Analyzer scopes (if they don't exist already) and analyze them
#       Specify DELETE to direct the script to delete Network Access Analyzer scopes which have been provisioned (located by scope name tag)
#       In order to REDEPLOY scopes, utilize delete to remove all scopes, modify the Network Access Analyzer JSON file, and then execute with CREATE_ANALYZE
#   5) Configure SCOPE_NAME_VALUE to specify the name tag which will be assigned to the scope. This tag is used to locate the scope for analysis
#   6) Configure EXCLUSIONS_FILE to specify exclusions which will be removed from output during the JSON data parse
#   7) Configure SCOPE_FILE to specify the file which will contain the Network Access Analyzer scope to be deployed
#   8) Configure S3_BUCKET to specify the existing S3 bucket which will have findings uploaded to, as well as where the EXCLUSIONS_FILE may be located.
#   9) Configure PARALLELISM for the number of accounts to process simultaneously
#   10) Configure S3_EXCLUSION_FILE is set to true by default. This instructs the script to download the exclusion file present in s3://S3_BUCKET/EXCLUSIONS_FILE
#       and overwrites the local copy on EC2 upon script execution. Set to false to utilize a local exclusion file without the s3 download copy
#   11) Configure FINDINGS_TO_CSV to specify if findings should be output to CSV
#   12) Configure FINDINGS_TO_SH to specify if findings should be import into Security Hub

SPECIFIC_ACCOUNTID_LIST="allaccounts"
#SPECIFIC_ACCOUNTID_LIST="123456789012 210987654321"

REGION_LIST="us-east-1"
#REGION_LIST="us-east-1 us-east-2"

IAM_CROSS_ACCOUNT_ROLE="NAAExecRole"

SCRIPT_EXECUTION_MODE="CREATE_ANALYZE"

SCOPE_NAME_VALUE="naa-external-ingress"

EXCLUSIONS_FILE="naa-exclusions.csv"

SCOPE_FILE="naa-scope.json"

S3_BUCKET="SetS3Bucket"

PARALLELISM="10"

S3_EXCLUSION_FILE="true"

FINDINGS_TO_CSV="YES"

FINDINGS_TO_SH="NO"

#########################################

#Create the network access analyzer scope JSON file
cat << EOF > $SCOPE_FILE
{
    "MatchPaths": [
        {
            "Source": {
                "ResourceStatement": {
                    "ResourceTypes": [
                        "AWS::EC2::InternetGateway"
                    ]
                }
            },
            "Destination": {
                "ResourceStatement": {
                    "ResourceTypes": [
                        "AWS::EC2::NetworkInterface"
                    ]
                }
            }
        }
    ]
}
EOF

#Copy EXCLUSIONS_FILE from S3 to the local EC2 if enabled.  Allows for exclusion file update within bucket and copied to EC2 upon script execution
if [[ "$S3_EXCLUSION_FILE" == "true" ]]; then
    #Copy exclusion file from S3 bucket to EC2
    aws s3 cp s3://$S3_BUCKET/$EXCLUSIONS_FILE .
    #If an error occurs with the copy (most likely to initial execution and doens't yet exist), create a local exclusion file and copy to the S3 bucket
    if [ $? = 1 ]; then
        echo ""
        echo "There was an error copying the exclusion file from s3://$S3_BUCKET/$EXCLUSIONS_FILE"
        echo "If this is the first execution of the script, this is expected as the exclusion file doesn't yet exist in S3"
        echo "A local $EXCLUSIONS_FILE will be created if it doesn't exist and copied to $S3_BUCKET"
        echo ""
        if [ ! -f $EXCLUSIONS_FILE ]; then
          echo "Local exclusions file file not found.  Creating..."
          echo "resource_id,secgroup_id,sgrule_cidr,sgrule_portrange" > $EXCLUSIONS_FILE
        fi
        aws s3 cp $EXCLUSIONS_FILE s3://$S3_BUCKET/$EXCLUSIONS_FILE
        if [ $? = 1 ]; then
          echo "There was an error copying the exclusion file $EXCLUSIONS_FILE to the S3 Bucket $S3_BUCKET"
          echo "Review IAM and/or S3 bucket permissions"
        fi
    fi
elif [[ "$S3_EXCLUSION_FILE" == "false" ]]; then
    #Create local exclusions file if it doesn't exist
    if [ ! -f $EXCLUSIONS_FILE ]; then
        echo "Local exclusions file file not found.  Creating..."
        echo "resource_id,secgroup_id,sgrule_cidr,sgrule_portrange" > $EXCLUSIONS_FILE
    fi
fi

#Create default exclusions file if it doesn't exist
if [ ! -f $EXCLUSIONS_FILE ]; then
    echo "Exclusions file file not found.  Creating..."
    echo "resource_id,secgroup_id,sgrule_cidr,sgrule_portrange" > $EXCLUSIONS_FILE
fi

#Create default aws cli config file with default region for commands if it doesn't exist.
if [ ! -f ~/.aws/config ]; then
    echo ""
    echo "AWS Config file not found.  Creating..."
    aws configure set region `aws ec2 describe-availability-zones --output text --query 'AvailabilityZones[0].[RegionName]'`
fi

#Capture starting aws sts creds
capture_starting_session() {
    export ORIG_AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID
    export ORIG_AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY
    export ORIG_AWS_SESSION_TOKEN=$AWS_SESSION_TOKEN
}
capture_starting_session

# Determine the executing account AWS Number and Partition
CALLER_IDENTITY_ARN=$(aws sts get-caller-identity --output text --query "Arn")
AWSPARTITION=$(echo "$CALLER_IDENTITY_ARN" | cut -d: -f2)
echo ""


# Function to Assume Role to Management Account and Create Session
management_account_session() {
    AWSMANAGEMENT=$(aws organizations describe-organization --query Organization.MasterAccountId --output text)
    echo "AWS Organization Management Account: $AWSMANAGEMENT"
    echo ""
    echo "Assuming IAM Role in Management account to list all AWS Org accounts..."
    role_credentials=$(aws sts assume-role --role-arn arn:$AWSPARTITION:iam::$AWSMANAGEMENT:role/$IAM_CROSS_ACCOUNT_ROLE --role-session-name MgmtAccount --output json)
    AWS_ACCESS_KEY_ID=$(echo "$role_credentials" | jq -r .Credentials.AccessKeyId)
    AWS_SECRET_ACCESS_KEY=$(echo "$role_credentials" | jq -r .Credentials.SecretAccessKey)
    AWS_SESSION_TOKEN=$(echo "$role_credentials" | jq -r .Credentials.SessionToken)
    export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
}

return_starting_session() {
    export AWS_ACCESS_KEY_ID=$ORIG_AWS_ACCESS_KEY_ID
    export AWS_SECRET_ACCESS_KEY=$ORIG_AWS_SECRET_ACCESS_KEY
    export AWS_SESSION_TOKEN=$ORIG_AWS_SESSION_TOKEN
}

execute_code() {
    #Assume role in each account
    echo "Assessing AWS Account: $1, using Role: $IAM_CROSS_ACCOUNT_ROLE"
    role_credentials=$(aws sts assume-role --role-arn arn:$AWSPARTITION:iam::$1:role/$IAM_CROSS_ACCOUNT_ROLE --role-session-name NAAAnalyze --output json)
    AWS_ACCESS_KEY_ID=$(echo "$role_credentials" | jq -r .Credentials.AccessKeyId)
    AWS_SECRET_ACCESS_KEY=$(echo "$role_credentials" | jq -r .Credentials.SecretAccessKey)
    AWS_SESSION_TOKEN=$(echo "$role_credentials" | jq -r .Credentials.SessionToken)
    export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN

    #Process each region in the $REGION_LIST array
    for region in $REGION_LIST; do
        {
            echo "Processing account: $1 / Region: $region"

            if [[ "$SCRIPT_EXECUTION_MODE" == "CREATE_ANALYZE" ]]; then
                #Create Subfolder for finding output
                mkdir -p naaoutput

                #Locate ScopeId and insert into variable.. Use this to discover the already existing scope for future analysis
                echo "Account: $1 / Region: $region - Detecting Network Access Analyzer scope..."
                ScopeId=$(aws ec2 describe-network-insights-access-scopes --region $region --filters Name=tag:Name,Values=$SCOPE_NAME_VALUE --query 'NetworkInsightsAccessScopes[].NetworkInsightsAccessScopeId' --output text)

                if [ -z $ScopeId ]; then
                    #Create Scope
                    echo "Account: $1 / Region: $region - Network Access Analyzer scope not detected.  Creating new scope..."
                    ScopeId=$(aws ec2 create-network-insights-access-scope --region $region --tag-specifications "ResourceType=network-insights-access-scope,Tags=[{Key=Name,Value=$SCOPE_NAME_VALUE}]" --cli-input-json file://$SCOPE_FILE | jq -r '.NetworkInsightsAccessScope.NetworkInsightsAccessScopeId')
                else
                    #Continue with Analysis of existing scope
                    echo "Account: $1 / Region: $region - Network Access Analyzer Scope detected."
                fi

                #Start Analysis and insert the AnalysisID into variable
                echo "Account: $1 / Region: $region - Continuing analysis with ScopeID.  Accounts with many resources may take up to one hour"
                AnalysisId=$(aws ec2 --region $region start-network-insights-access-scope-analysis --network-insights-access-scope-id $ScopeId | jq -r '.NetworkInsightsAccessScopeAnalysis.NetworkInsightsAccessScopeAnalysisId')

                #Monitor Status of AnalysisID.  While processing, Status is running and when done, changes to succeeded
                i=0
                Status="running"
                while [ $i -lt 240 ]
                do
                    ((i++))
                    Status=$(aws ec2 --region $region describe-network-insights-access-scope-analyses --network-insights-access-scope-analysis-id $AnalysisId | jq -r '.NetworkInsightsAccessScopeAnalyses[].Status')
                    if [[ "$Status" != "running" ]]; then
                        break
                    fi
                sleep 15
                done

                #Proceed depending on status of the scope analysis (If $Status == succeeded, bypass if statements)
                if [[ "$Status" == "running" ]]; then
                    echo "Account: $1 / Region: $region / AnalysisId: $AnalysisId - Analysis timed out after 1 hour and may still be running"
                    echo "Account: $1 / Region: $region / AnalysisId: $AnalysisId - Please review and execute again later"
                    return 0
                elif [[ "$Status" == "failed" ]]; then
                    AnalysisStatus=$(aws ec2 --region $region describe-network-insights-access-scope-analyses --network-insights-access-scope-analysis-id $AnalysisId | jq -r '.NetworkInsightsAccessScopeAnalyses[].StatusMessage')
                    echo "Account: $1 / Region: $region / AnalysisId: $AnalysisId - Analysis failed to complete. Please review"
                    echo "Account: $1 / Region: $region / AnalysisId: $AnalysisId - Status Message: $AnalysisStatus"
                    return 0
                fi

                #Output findings from Analysis in JSON format.
                echo "Account: $1 / Region: $region - Outputting findings..."
                aws ec2 --region $region get-network-insights-access-scope-analysis-findings --network-insights-access-scope-analysis-id $AnalysisId --no-cli-pager > naaoutput/naa-unprocessed-$1-$region.json

            elif [[ "$SCRIPT_EXECUTION_MODE" == "DELETE" ]]; then
                #Locate ScopeId and insert into variable.. Use this to discover the already existing scope for future analysis
                ScopeId=$(aws ec2 describe-network-insights-access-scopes --region $region --filters Name=tag:Name,Values=$SCOPE_NAME_VALUE --query 'NetworkInsightsAccessScopes[].NetworkInsightsAccessScopeId' --output text)

                #Validate NAA Scope exists.  If not, exit loop
                if [ -z $ScopeId ]; then
                    continue
                fi

                #Generate AnalysisIdList and build space separated list
                AnalysisIdList=$(aws ec2 describe-network-insights-access-scope-analyses --region $region --network-insights-access-scope-id $ScopeId | jq -r '.NetworkInsightsAccessScopeAnalyses[].NetworkInsightsAccessScopeAnalysisId' |tr "\n" " ")

                #Delete each AnalysisId from the list
                for AnalysisId in $AnalysisIdList; do
                    {
                        #Delete AnalysisId associated with Scope
                        echo "Account: $1 / Region: $region - Deleting Analysis $AnalysisId"
                        aws ec2 delete-network-insights-access-scope-analysis --region $region --network-insights-access-scope-analysis-id $AnalysisId
                    }
                done

                #Delete Scope
                echo "Account: $1 / Region: $region - Deleting Scope $ScopeId"
                aws ec2 delete-network-insights-access-scope --region $region --network-insights-access-scope-id $ScopeId
            fi
        }
    done

    echo "Account: $1 / Region: $region - Completed"
    echo ""
    echo ""

    #Return to original credentials
    return_starting_session
}

#Monitor the number of background processes and return to task execution for loop when bg jobs less than PARALLELISM limit
process_monitor() {
    while [ "$(jobs | wc -l)" -ge $PARALLELISM ]
    do
        sleep 2
    done
}

if [[ "$SPECIFIC_ACCOUNTID_LIST" == "allaccounts" ]]; then
    # Lookup All Accounts in AWS Organization
    management_account_session
    ACCOUNTS_TO_PROCESS=$(aws organizations list-accounts --output text --query 'Accounts[?Status==`ACTIVE`].Id')
    echo ""

    # Return to original credentials after generating list of AWS accounts
    return_starting_session
else
    ACCOUNTS_TO_PROCESS=$SPECIFIC_ACCOUNTID_LIST
fi

# Execute command against accounts
echo ""
echo "AWS Accounts being processed..."
echo "$ACCOUNTS_TO_PROCESS"
echo ""

#Process all accounts in the $ACCOUNTS_TO_PROCESS array, 8 at a time, and send them to the background
for accountId in $ACCOUNTS_TO_PROCESS; do
    test "$(jobs | wc -l)" -ge $PARALLELISM && process_monitor || true
    {
        execute_code $accountId
    } &
done

# Wait for all background processes to finish
wait

####
#### POST ACCOUNT AND REGION EXECUTION: COMMAND(S) BELOW TO BE EXECUTED ON RESULTS
####

#Set variable with timestamp for use with file generation
OUTPUT_SUFFIX=$(date +%m-%d-%Y-%H-%M)

if [[ "$SCRIPT_EXECUTION_MODE" == "CREATE_ANALYZE" ]]; then
    echo ""
    echo "Network Access Analyzer assessments have been completed against all accounts"
    echo ""
    echo "Proceeding to Post Processing"
    echo ""

    #Remove previously processed data and zip
    rm -f naaoutput/naa-findings*.csv naaoutput/naa-unprocessed*.zip naaoutput/naa-processfindingsresults*.txt

    #Generate a list of individual output files and process them into csv with python
    FINDING_FILES=$(ls naaoutput/naa-unprocessed*.json)

    #Loop through files and process from json into csv
    for finding in $FINDING_FILES; do
        {
            echo "Processing file: $finding" | tee -a naaoutput/naa-processfindingsresults-$OUTPUT_SUFFIX.txt
            python3 ./naa-processfindings.py  -i $finding -o naaoutput/naa-findings-$OUTPUT_SUFFIX.csv -e $EXCLUSIONS_FILE -c $FINDINGS_TO_CSV -s $FINDINGS_TO_SH >> naaoutput/naa-processfindingsresults-$OUTPUT_SUFFIX.txt 2>&1
        }
    done

    #Zip all individual findings into single file for archive
    echo ""
    echo "Zip files"
    zip naaoutput/naa-unprocessed-$OUTPUT_SUFFIX.zip naaoutput/naa-unprocessed*.json naaoutput/naa-processfindingsresults-$OUTPUT_SUFFIX.txt

    #Remove unprocessed finding files which now exist within the zip file
    rm -f naaoutput/naa-unprocessed-*.json

    #If the analysis contains findings, copy zip file to S3 bucket (A CSV file with 1 row contains only a header and no findings)
    NAAFINDINGSWC=$(wc -l < naaoutput/naa-findings-$OUTPUT_SUFFIX.csv)
    if [[ $NAAFINDINGSWC -gt 1 ]]; then
        aws s3 cp ./naaoutput s3://$S3_BUCKET --recursive --exclude "*" --include "naa*.zip" --include "naa-findings*.csv"
    fi

    echo ""
    echo "view output at command line with:"
    echo "column -s, -t < naaoutput/naa-findings-$OUTPUT_SUFFIX.csv | less -#2 -N -S"
fi

echo ""
echo "Processing has been executed against all accounts in the AWS account list"
echo " "
