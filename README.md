# AWS Cloudwatch Logs Checker

## Description
This is a helper script that checks all running windows instances within an AWS region and looks to see if they are shipping logs to Cloudwatch Logs.
The script allows output as json, csv or just a text summary.

## Usage
```
# Output as json
python log_checker.py --hours {hours in past to check} --json

# Output as csv file
python log_checker.py --hours {hours in past to check} --csv

# Use different AWS Profile
python log_checker.py --profile {other_profile} --hours {hours in past to check} --csv

# Check if SSM is running on the instance as well
python log_checker.py --hours {hours in past to check} --ssm --json
```
