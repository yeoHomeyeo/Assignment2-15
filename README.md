## Assignment2-15
## Secret Management

### What is needed to authorize your EC2 to retrieve secrets from the AWS Secret Manager?
- To authorize an EC2 instance to retrieve secrets from AWS Secrets Manager, create an IAM role with the necessary permissions and attach it to the EC2 instance

- Steps:
  - Create an IAM Role:
    - Create an IAM role that the EC2 instance can assume.
    - Attach a policy to this role that grants permissions to access the specific secret in AWS Secrets Manager.

  - Attach the IAM Role to the EC2 Instance:
    - Attach the IAM role to the EC2 instance.

  - Retrieve the Secret:
    - Application running on the EC2 instance can now retrieve the secret using the AWS SDK or CLI.
```
import boto3
import json

def get_secret():
    secret_name = "prod/cart-service/credentials"
    region_name = "us-east-1"

    #Create a Secrets Manager client
    client = boto3.client('secretsmanager', region_name=region_name)

    try:
        get_secret_value_response = client.get_secret_value(SecretId=secret_name)
    except Exception as e:
        raise e
    else:
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
            return json.loads(secret)
        else:
            decoded_binary_secret = base64.b64decode(get_secret_value_response['SecretBinary'])
            return decoded_binary_secret

#Example usage
secret = get_secret()
print(secret)
```

### Derive the IAM policy (i.e. JSON)?

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",    # allows the specified actions
            "Action": [
                "secretsmanager:GetSecretValue", # Allows retrieving the secret value
                "secretsmanager:DescribeSecret" # Allows describing the secret (optional, but useful for debugging)
            ],
            "Resource": "arn:aws:secretsmanager:region:account-id:secret:secret-name" # replace with actual variables
        }
    ]
}
```


### Using the secret name prod/cart-service/credentials, derive a sensible ARN as the specific resource for access
```
arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/cart-service/credentials
```

- Region: The AWS region where the secret is stored (us-east-1)
- Account-id: Your AWS account ID (123456789012)
- Secret-name: The name of the secret ( prod/cart-service/credentials)
