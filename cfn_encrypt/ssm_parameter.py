import cfnresponse, logging, traceback, boto3
from random import choice
from string import ascii_uppercase, ascii_lowercase, digits
from hmac import new as newkey
from hashlib import sha256
from base64 import b64encode

from botocore.config import Config
from botocore.exceptions import ClientError


def parameter_exist(name):
    response = boto3.client('ssm').describe_parameters(
        ParameterFilters=[{
            'Key': 'Name',
            'Values': [
                name
            ]
        }]
    )
    return len(response["Parameters"]) > 0

def get_property(rp, name:str):
    return rp[name] if name in rp else None


def handler(event, context):
    logger = logging.getLogger("crypto_cfn")
    logger.setLevel(logging.DEBUG)
    rp = event["ResourceProperties"]
    name = rp["Name"]
    value = None

    config=Config(
        retries=dict(
            max_attempts=10
        )
    )
    try:
        if event["RequestType"] in ["Create", "Update"]:
            if event["RequestType"] == "Create" and parameter_exist(name):
                raise NameError("A Parameter named {} already exists".format(name))

            generate_password = get_property(rp, "GeneratePassword")
            value = get_property(rp, "Value")

            if value and generate_password in ['true', 'True', '1', True, 1]:
                raise ValueError("Property Value and GeneratePassword cannot be used at the same time")

            if generate_password in ['true', 'True', '1', True, 1]:

                password_length = get_property(rp, "GeneratePasswordLength")
                allow_specials = get_property(rp, "GeneratePasswordAllowSpecialCharacters")
                if not password_length:
                    raise ValueError("The Resource property GeneratePasswordLength is required")

                try:
                    password_length = int(password_length)
                except:
                    raise ValueError("The Resource property GeneratePasswordLength must be an integer")


                charset = ascii_uppercase + ascii_lowercase + digits
                if allow_specials and allow_specials in ['true', 'True', '1', True, 1]:
                    charset = charset + "!\"#$%&'()*+,-./:;<=>?@[\]^_`{|}~"

                value = ''.join(choice(charset) for i in range(password_length))

            is_smtp_user = get_property(rp, "GenerateSMTPPassword")
            iam_secret = get_property(rp, "IAMSecretKey")
            if is_smtp_user:
                if not iam_secret:
                    raise ValueError("To create an SMTP password the IAM secret access key is required")
                message = b"SendRawEmail"
                result = bytearray(b'\x02')
                result.extend(newkey(iam_secret.encode('utf-8'), message, digestmod=sha256).digest())
                value = b64encode(result).decode('ascii')

            if not value:
                raise ValueError("Either generate a password or set a value")

            response = boto3.client('ssm', config=config).put_parameter(
                Name=name,
                Description=rp["Description"],
                Value=value,
                Type="SecureString",
                KeyId=rp["KeyId"],
                Overwrite=True
            )

            logger.info("Successfully stored parameter {}".format(name))

            cfnresponse.send(event, context, cfnresponse.SUCCESS, response, name)
        elif event["RequestType"] in ["Delete"]:
            try:
                boto3.client('ssm', config=config).delete_parameter(
                    Name=event["PhysicalResourceId"],
                )
            except ClientError as e:
                if e.response['Error']['Code'] not in ['ParameterNotFound']:
                    raise
                pass
            logger.info("Successfully deleted parameter: {}".format(name))
            cfnresponse.send(event, context, cfnresponse.SUCCESS, None, name)

    except Exception as ex:
        logger.error("Failed to %s parameter: %s", event["RequestType"], name)
        logger.debug("Stack trace %s", traceback.format_exc())
        if event["RequestType"] in ["Create", "Update", "Delete"]:
            cfnresponse.send(event, context, cfnresponse.FAILED, None, "0")
        else:
            cfnresponse.send(event, context, cfnresponse.SUCCESS, None, "0")
