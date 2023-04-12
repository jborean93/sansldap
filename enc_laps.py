import base64
import sys
import typing as t

from ruamel import yaml

from sansldap._pkcs7 import ContentInfo, EnvelopedData, KEKRecipientInfo, RecipientInfo, ManagedPasswordId

data = base64.b64decode(
    "MIIBZAYJKoZIhvcNAQcDoIIBVTCCAVECAQIxggEdooIBGQIBBDCB3ASBhAEAAABLRFNLAgAAAGkBAAAPAAAADgAAAKhPxrqQ6HyREJCD57D4WZYgAAAAGAAAABgAAABoD4CvgPwuwKPV3MBhp1Ny23XtDi/ChsKXOPzRmoOkHWQAbwBtAGEAaQBuAC4AdABlAHMAdAAAAGQAbwBtAGEAaQBuAC4AdABlAHMAdAAAADBTBgkrBgEEAYI3SgEwRgYKKwYBBAGCN0oBATA4MDYwNAwDU0lEDC1TLTEtNS0yMS00MTUxODA4Nzk3LTM0MzA1NjEwOTItMjg0MzQ2NDU4OC01MTIwCwYJYIZIAWUDBAEtBCgKJ5Img1sKLFLY7tKVtobKsV+Y8V/vfa2cMqGWwFBVaP6vCzUQNwXeMCsGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMTpn5UgmifKB/9LhQAgEQZt7BTBIkRTaH91BdNI7EO4eiLWpwDbXyGNM8OA6XlyYP1BQ4e/Do8eqEHofY6nKa1jeW+CvB96iBUGhk4Cz4BT9jw24wF4zEGE+BhdIvNqF+qWoXDo8Qj/nl8XjWuIIUazIqF4vdBZXEJoQ8zj9zEa9rya9VRGWzm9Y+m6/vD4ARegUSqGxQgwPlZosgx7szMl8="
)


def get_recipient_info(info: RecipientInfo) -> t.Dict[str, t.Any]:
    data = {
        "Choice": info.choice,
        "Type": type(info).__name__,
    }
    if isinstance(info, KEKRecipientInfo):
        # group_key = ManagedPasswordId.unpack(info.kekid.key_identifier)

        other_id = None
        other_value = None
        if info.kekid.other:
            other_id = info.kekid.other.key_attr_id
            if other_id == "1.3.6.1.4.1.311.74.1" and info.kekid.other.key_attr:
                other_value = base64.b16encode(info.kekid.other.key_attr or b"").decode()
            else:
                other_value = base64.b16encode(info.kekid.other.key_attr or b"").decode()

        data.update(
            {
                "Version": info.version,
                "KekId": {
                    "KeyIdentifier": base64.b16encode(info.kekid.key_identifier).decode(),
                    "Date": info.kekid.date,
                    "OtherId": other_id,
                    "OtherValue": other_value,
                },
                "Algorithm": {
                    "Id": info.key_encryption_algorithm.algorithm,
                    "Parameters": base64.b16encode(info.key_encryption_algorithm.parameters or b"").decode(),
                },
                "EncryptedKey": base64.b16encode(info.encrypted_key).decode(),
            }
        )

    return data


# https://learn.microsoft.com/en-us/windows/win32/seccng/protected-data-format
# Protected data is stored as an ASN.1 encoded BLOB. The data is formatted as
# CMS (certificate message syntax) enveloped content. The digital envelope
# contains encrypted content, recipient information that contains an encrypted
# content encryption key (CEK), and a header that contains information about
# the content, including the unencrypted protection descriptor rule string.

ci = ContentInfo.unpack(data)
if ci.content_type != EnvelopedData.content_type:
    raise ValueError("Unknown ContentInfo type")

enveloped_data = EnvelopedData.unpack(ci.content)
enc_ci = enveloped_data.encrypted_content_info

info = {
    "Recipients": [get_recipient_info(i) for i in enveloped_data.recipient_infos],
    "EncryptedContentInfo": {
        "ContentType": enc_ci.content_type,
        "Algorithm": {
            "Id": enc_ci.content_encryption_algorithm.algorithm,
            "Parameters": base64.b16encode(enc_ci.content_encryption_algorithm.parameters or b"").decode(),
        },
    },
}

y = yaml.YAML()
y.default_flow_style = False
y.dump(info, sys.stdout)
