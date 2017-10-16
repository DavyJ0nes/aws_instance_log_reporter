# AWS Cloudwatch Logs Checker

## Description
This is a helper script that checks all running  instances within an AWS region and looks to see if they are shipping logs to Cloudwatch Logs.
The script allows output as json, csv or just a text summary.

By default it will filter out instances where platform == windows. You can use the `--windows` flag to output only windows instances.

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

# Check Windows Instances Only and output to csv
python log_checker.py --hours {hours in past to check} --windows --csv
```

## Caveat
This is in dire need of refactoring. It is functional but is a bit of a mess and performance could be improved.
