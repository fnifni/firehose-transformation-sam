# AWS Kinesis Firehose Transformation with Lambda

This pattern deploys a Kinesis Data Firehose that invokes a Lambda function to transform incoming source data and deliver the transformed data to destinations. 

more information see [Redact sensitive data from streaming data in near-real time using Amazon Comprehend and Amazon Kinesis Data Firehose](https://aws.amazon.com/jp/blogs/machine-learning/redact-sensitive-data-from-streaming-data-in-near-real-time-using-amazon-comprehend-and-amazon-kinesis-data-firehose/)

## Requirements

* [Create an AWS account](https://portal.aws.amazon.com/gp/aws/developer/registration/index.html) if you do not already have one and log in. The IAM user that you use must have sufficient permissions to make necessary AWS service calls and manage AWS resources.
* [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html) installed and configured
* [Git Installed](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git)
* [AWS Serverless Application Model](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-sam-cli-install.html) (AWS SAM) installed

## Deployment Instructions

1. Create a new directory, navigate to that directory in a terminal and clone the GitHub repository:
    ``` 
    git clone https://github.com/aws-samples/serverless-patterns
    ```
1. Change directory to the pattern directory:
    ```
    cd firehose-transformation-sam
    ```
1. From the command line, use AWS SAM to build and deploy the AWS resources for the pattern as specified in the template.yml file:
    ```
    sam build
    sam deploy --guided
    ```
1. During the prompts:
    * Enter a stack name
    * Enter the desired AWS Region
    * Enter a bucket name for edited data
    * Enter a bucket name for raw data
    * Allow SAM CLI to create IAM roles with the required permissions.

    Once you have run `sam deploy --guided` mode once and saved arguments to a configuration file (samconfig.toml), you can use `sam deploy` in future to use these defaults.

1. Note the outputs from the SAM deployment process. These contain the resource names and/or ARNs which are used for testing.

## How it works

This SAM template deploys the resources and the IAM permissions required to run the application.

This pattern deploys a Kinesis Firehose Delivery Stream, a transformation Lambda function, a destination S3 bucket, and all of the additional infrastructure required for the pattern.  

Kinesis Data Firehose can invoke a Lambda function to transform incoming source data and deliver the transformed data to destinations. In this architecture, Kinesis Data Firehose then invokes the specified Lambda function asynchronously with each buffered batch using the AWS Lambda synchronous invocation mode. The transformed data is sent from Lambda to Kinesis Data Firehose. Kinesis Data Firehose then sends it to the destination S3 bucket when the specified destination buffering size or buffering interval is reached, whichever happens first.

==============================================

## Testing

see [Redact sensitive data from streaming data in near-real time using Amazon Comprehend and Amazon Kinesis Data Firehose](https://aws.amazon.com/jp/blogs/machine-learning/redact-sensitive-data-from-streaming-data-in-near-real-time-using-amazon-comprehend-and-amazon-kinesis-data-firehose/)


Or nagivate to the S3 console and manually verify that the demo data has been sent to S3

## Cleanup
 
1. Delete the stack
    ```bash
    aws cloudformation delete-stack --stack-name STACK_NAME
    ```
1. Confirm the stack has been deleted
    ```bash
    aws cloudformation list-stacks --query "StackSummaries[?contains(StackName,'STACK_NAME')].StackStatus"
    ```
----
Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.

SPDX-License-Identifier: MIT-0
