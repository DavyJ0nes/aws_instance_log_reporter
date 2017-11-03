# AWS Cloudwatch Logs Checker

## Description
This is a helper script that checks all running  instances within an AWS region and looks to see if they are shipping logs to Cloudwatch Logs.
The script allows output as json, csv or just a text summary.

By default it will filter out instances where platform == windows. You can use the `--windows` flag to output only windows instances.

Be aware that this script will use the default aws profile when running. You will need to use `--profile` to specify what awscli profile you want to use.

If you have multiple accounts that you want to query then you will need to run the script within a loop. There are some examples outlined below for bash and Windows.

## Usage
```
# Output as json (with default profile)
python log_checker.py --hours {hours in past to check} --json

# Output as csv file (with default profile)
python log_checker.py --hours {hours in past to check} --csv

# Use different AWS Profile (specifying profile)
python log_checker.py --profile {other_profile} --hours {hours in past to check} --csv

# Check if SSM is running on the instance as well (with default profile)
python log_checker.py --hours {hours in past to check} --ssm --json

# Check Windows Instances Only and output to csv (with default profile)
python log_checker.py --hours {hours in past to check} --windows --csv
```

## Running in Loop
### Bash
```
#!/bin/bash
set -ef

# Setting Run Vars
env=$1

# Usage Instructions
if [ "$env" == "" ]; then
  echo "Usage:"
  echo "./run_all_accounts.sh {env}"
  echo "exiting..."
  exit 1
fi

## In this example the .aws/config file entries look like:
## [profile p-sandbox]

# Get list of aws profiles from config file
aws_profile_string=$(grep "profile $env-" ~/.aws/config | awk -F " " '{print $2}' | tr -d "]")

# convert string to array
aws_profiles=(${aws_profile_string///\n/ })

# Iterate over the array
for e in "${!aws_profiles[@]}"; do
  echo "---------------------------------"
  echo "Running Script on: ${aws_profiles[e]}"
  python log_checker.py --profile "${aws_profiles[e]}" --hours 72 --csv
done
```

## Caveat
This is in dire need of refactoring. It is functional but is a bit of a mess and performance could be improved.
