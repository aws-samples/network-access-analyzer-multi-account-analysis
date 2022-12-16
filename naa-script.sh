#!/bin/bash -e

#Requirements:
#   1) Install Dependencies on the AmazonLinux2 Instance. (AWS CLI and JQ are primary requirements)
#       sudo yum update -y
#       sudo yum remove -y awscli
#       curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
#       unzip awscliv2.zip
#       sudo ./aws/install
#       ln -s /usr/local/bin/aws /usr/local/sbin/aws
#       sudo yum install jq -y
#   2) IAM Role attached to the EC2 instance has to permission to assume "IAM_CROSS_ACCOUNT_ROLE"
#   3) SPECIFIC_ACCOUNTID_LIST: List specific accounts (SPACE DELIMITED) if you wish to run the command only against those,
#        or leave allaccounts to detect and execute against all accounts in the AWS Org
#   4) REGION_LIST (SPACE DELIMITED): Specify regions to execute commands in
#   5) IAM_CROSS_ACCOUNT_ROLE: The IAM Role name created for cross account.
#   7) SCRIPT_EXECUTION_MODE:
#       Specify CREATE_ANALYZE to direct the script to create NAA scopes (if they don't exist aleady) and analyze them
#       Specify DELETE to direct the script to delete NAA scopes which have been provisioned (located by scope name tag)
#       In order to REDEPLOY scopes, utilize delete to remove all scopes, modify the NAA JSON file, and then execute with CREATE_ANALYZE
#   8) Configure SCOPE_NAME_VALUE to specify the name tag which will be assigned to the scope.  This tag is used to locate the scope for analysis
#   9) Configure EXCLUSIONS_FILE to specify exclusions which will be removed from output during the json to csv conversion
#   10) Configure S3_BUCKET to specify the existing S3 bucket which will have findings uploaded to, as well as where the exclusion_file may be located
#   11) Configure PARALLELISM for the number of accounts to process simultaneously
#   12) S3_EXCLUSION_FILE is set to true by default.  This instructs the script to download the exclusion file present in s3://S3_BUCKET/EXCLUSIONS_FILE
#       and overwrites the local copy on EC2 upon script execution. Set to false to utilize a local exclusion file without the s3 download copy

#########################################
#Variables to be modified:

SPECIFIC_ACCOUNTID_LIST="allaccounts"
#SPECIFIC_ACCOUNTID_LIST="123456789012 210987654321"

REGION_LIST="us-east-1"
#REGION_LIST="us-east-1 us-east-2"

IAM_CROSS_ACCOUNT_ROLE="NAAExecRole"

SCRIPT_EXECUTION_MODE="CREATE_ANALYZE"
#SCRIPT_EXECUTION_MODE="DELETE"

SCOPE_NAME_VALUE="naa-external-ingress"

EXCLUSIONS_FILE="naa-exclusions.csv"

SCOPE_FILE="naa-scope.json"

S3_BUCKET="SpecifyS3BucketCreatedForReports"

PARALLELISM="10"

S3_EXCLUSION_FILE=true
#S3_EXCLUSION_FILE=false

#########################################

#Continue with rest of script if an error is encountered
set +e

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

#Copy EXCLUSIONS_FILE from S3 to the local EC2 if enabled.  Allows for exclusion file update within bucket and auto-copy to EC2
if $S3_EXCLUSION_FILE; then 
    aws s3 cp s3://$S3_BUCKET/$EXCLUSIONS_FILE .
    if [ $? = 1 ]; then
        echo "There was an error copying the exclusion file from path s3://$S3_BUCKET/$EXCLUSIONS_FILE"
        echo ""
        echo "A local $EXCLUSIONS_FILE will be created if one does not exist already.  This file may be used as a template or copied to $S3_BUCKET"
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
    aws configure set region us-east-1
fi

#Capture starting aws sts creds
capture_starting_session() {
    export ORIG_AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID
    export ORIG_AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY
    export ORIG_AWS_SESSION_TOKEN=$AWS_SESSION_TOKEN
}
capture_starting_session

# Find AWS Management Account
echo ""
AWSMANAGEMENT=$(aws organizations describe-organization --query Organization.MasterAccountId --output text)
echo "AWS Management Account: $AWSMANAGEMENT"
echo ""

# Function to Assume Role to Management Account and Create Session
management_account_session() {
    echo "Assuming IAM Role in Management account to list all AWS Org accounts..."
    role_credentials=$(aws sts assume-role --role-arn arn:aws:iam::$AWSMANAGEMENT:role/$IAM_CROSS_ACCOUNT_ROLE --role-session-name MgmtAccount --output json)
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
    role_credentials=$(aws sts assume-role --role-arn arn:aws:iam::$1:role/$IAM_CROSS_ACCOUNT_ROLE --role-session-name MgmtAccount --output json)
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
    rm -f naaoutput/naa-findings*.csv naaoutput/naa-unprocessed*.zip

    #Generate a list of individual output files and process them into csv with python
    FINDING_FILES=$(ls naaoutput/naa-unprocessed*.json)

    #Loop through files and process from json into csv
    for finding in $FINDING_FILES; do
        {
            echo "Processing file: $finding" | tee -a naaoutput/naa-findings2csvresults.txt
            python3 ./naa-findings2csv.py  -i $finding -o naaoutput/naa-findings-$OUTPUT_SUFFIX.csv -e $EXCLUSIONS_FILE >> naaoutput/naa-findings2csvresults.txt 2>&1
        }
    done

    #Zip all individual findings into single file for archive
        echo ""
    echo "Zip files"
    zip naaoutput/naa-unprocessed-$OUTPUT_SUFFIX.zip naaoutput/naa-unprocessed*.json naaoutput/naa-findings2csvresults.txt

    #Remove unprocessed finding files which now exist within the zip file
    rm -f naaoutput/naa-unprocessed-*.json naaoutput/naa-findings2csvresults.txt

    #Copy zip file to S3 bucket
    aws s3 cp ./naaoutput s3://$S3_BUCKET --recursive --exclude "*" --include "naa*.zip" --include "naa-findings*.csv"

    echo ""
    echo "view output at command line with:"
    echo "column -s, -t < naaoutput/naa-findings-$OUTPUT_SUFFIX.csv | less -#2 -N -S"
fi

echo ""
echo "Processing has been executed against all accounts in the AWS account list"
echo " "
