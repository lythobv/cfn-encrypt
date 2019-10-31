from troposphere import cloudformation, AWSProperty, validators

try:
    unicode = unicode
except NameError:
    str = str
    basestring = (str, bytes)
    unicode = str
    bytes = str


class EncryptionContext(AWSProperty):
    props = {
        'Name': (basestring, True),
        'Value': (basestring, True)
    }


class Encrypt(cloudformation.AWSCustomObject):
    resource_type = "Custom::Encrypt"
    props = {
        'ServiceToken': (basestring, True),
        'Base64Data': (basestring, True),
        'KmsKeyArn': (basestring, True),
        'EncryptionContext': (EncryptionContext, False)
    }


class SecureParameter(cloudformation.AWSCustomObject):
    resource_type = "Custom::SecureParameter"
    props = {
        'ServiceToken': (basestring, True),
        'Name': (basestring, True),
        'Value': (basestring, False),
        'Description': (basestring, True),
        'KeyId': (basestring, True),
        'GeneratePassword': (validators.boolean, False),
        'GeneratePasswordLength': (validators.positive_integer, False),
        'GeneratePasswordAllowSpecialCharacters': (validators.boolean, False),
        'GenerateSMTPPassword': (validators.boolean, False),
        'IAMSecretKey': (basestring, False),
    }


class GetSsmValue(cloudformation.AWSCustomObject):
    resource_type = "Custom::GetSsmValue"
    props = {
        'ServiceToken': (basestring, True),
        'Name': (basestring, True),
        'KeyId': (basestring, True),
        'Version': (validators.positive_integer, False)
    }
