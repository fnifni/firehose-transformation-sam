import json
import boto3
import os
import base64
import sys
import datetime

def lambda_handler(event, context):
    
    output = []
    
    for record in event['records']:

        # Gathers keys from enviroment variables and makes a list of desired keys to check for PII
        rawkeys = os.environ['keys']
        splitkeys = rawkeys.split(", ")
        print(splitkeys)

        # Add Dynamic Partioning for S3 buckets
        t_delta = datetime.timedelta(hours=9)
        JST = datetime.timezone(t_delta, 'JST')
        now = datetime.datetime.now(JST)

        partitionKeys = {}
        partitionKeys["region"] = context.invoked_function_arn.split(":")[3]
        partitionKeys["AWS_account"] = context.invoked_function_arn.split(":")[4]
        partitionKeys["eventDay"] = now.strftime('%Y%m%d')
        print(partitionKeys)

        #decode base64
        #Kinesis data is base64 encoded so decode here
        payloadraw=base64.b64decode(record["data"]).decode('utf-8')
        #Loads decoded payload into json
        payloadjsonraw = json.loads(payloadraw)
        
        # Creates Comprehend client
        comprehend_client = boto3.client('comprehend')
        
        
        # This codes handles the logic to check for keys, identify if PII exists, and redact PII if available. 
        for i in payloadjsonraw:
            # checks if the key found in the message matches a redact
            
            if i in splitkeys:
                print("Redact key found, checking for PII")
                payload = str(payloadjsonraw[i])
                # check if payload size is less than 100KB
                if sys.getsizeof(payload) < 99999:
                    print('Size is less than 100KB checking if value contains PII')
                    # Runs Comprehend ContainsPiiEntities API call to see if key value contains PII
                    pii_identified = comprehend_client.contains_pii_entities(Text=payload, LanguageCode='en')
                    
                    # If PII is not found, skip over key
                    if (pii_identified['Labels']) == []:
                        print('No PII found')
                    else:
                    # if PII is found, run through redaction logic
                        print('PII found redacting')
                        # Runs Comprehend DetectPiiEntities call to find exact location of PII
                        response = comprehend_client.detect_pii_entities(Text=payload, LanguageCode='en')
                        entities = response['Entities']
                        # creates redacted_payload which will be redacted
                        redacted_payload = payload
                        # runs through a loop that gathers necessary values from Comprehend API response and redacts values
                        for entity in entities:
                            char_offset_begin = entity['BeginOffset']
                            char_offset_end = entity['EndOffset']
                            redacted_payload = redacted_payload[:char_offset_begin] + '*'*(char_offset_end-char_offset_begin) + redacted_payload[char_offset_end:]
                        # replaces original value with redacted value
                        payloadjsonraw[i] = redacted_payload
                        print(str(payloadjsonraw[i]))
                else:
                    print ('Size is more than 100KB, skipping inspection')
            else:
                print("Key value not found in redaction list")
        
        redacteddata = json.dumps(payloadjsonraw)
        
        # adds inspected record to record
        output_record = {
            'recordId': record['recordId'],
            'result': 'Ok',
            'data' : base64.b64encode(redacteddata.encode('utf-8')),
            'metadata': {'partitionKeys': partitionKeys}
        }
        output.append(output_record)
        print(output_record)
        
    print('Successfully processed {} records.'.format(len(event['records'])))
    
    return {'records': output}