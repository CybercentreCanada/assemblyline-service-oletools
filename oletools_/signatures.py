"""Authenticode Signatures.

Functions for formatting OLE signature data as JSON
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from signify.authenticode import AuthenticodeSignedData, AuthenticodeSignerInfo, RFC3161SignedData
from signify.pkcs7 import SignedData, SignerInfo

if TYPE_CHECKING:
    from asn1crypto.core import Asn1Value
    from signify.x509 import Certificate


def format_certificate(cert: Certificate) -> dict[str, str]:
    """Format certificate metadata as a dictionary."""
    return {
        "subject": cert.subject.dn,
        "issuer": cert.issuer.dn,
        "serial": str(cert.serial_number),
        "valid_from": str(cert.valid_from),
        "valid_to": str(cert.valid_to),
    }


def describe_attribute(name: str, values: list[Asn1Value]) -> dict[str, Any]:
    """Represent an attribute as a JSON object."""
    if name in (
        "microsoft_time_stamp_token",
        "microsoft_spc_sp_opus_info",
        "counter_signature",
    ):
        return {name: "(elided)"}
    if name == "message_digest":
        return {name: values[0].native.hex()}
    if len(values) == 1:
        return {name: values[0].native}
    return {name: [value.native for value in values]}


def describe_signer_info(signer_info: SignerInfo) -> dict[str, Any]:
    """Repressent a SignerInfo as a JSON object."""
    result: dict[str, Any] = {
        "issuer": signer_info.issuer.dn,
        "serial": str(signer_info.serial_number),
        "digest_algorithm": signer_info.digest_algorithm.__name__,
        "digest_encryption_algorithm": signer_info.digest_encryption_algorithm,
        "encrypted_digest": signer_info.encrypted_digest.hex(),
    }

    if signer_info.authenticated_attributes:
        result["authenticated_attributes"] = [
            describe_attribute(*attribute) for attribute in signer_info.authenticated_attributes.items()
        ]
    if signer_info.unauthenticated_attributes:
        result["unauthenticated_attributes"] = [
            describe_attribute(*attribute) for attribute in signer_info.unauthenticated_attributes.items()
        ]

    if isinstance(signer_info, AuthenticodeSignerInfo):
        result["opus_info"] = {
            "program_name": signer_info.program_name,
            "more_info": signer_info.more_info,
            "publisher_info": signer_info.publisher_info,
        }

    if signer_info.countersigner:
        # SignerInfo.countersigner's type is a lie,
        # Subclass AuthenticodeSignerInfo's countersigner can be RFC3161SignedData
        # https://github.com/ralphje/signify/blob/42975a08d8738a9d107fda2b239288d0948f87e0/signify/authenticode/structures.py#L813
        countersigner: SignerInfo | RFC3161SignedData = signer_info.countersigner
        if isinstance(countersigner, SignerInfo):
            result["countersigner"] = {
                "signing_time": getattr(signer_info.countersigner, "signing_time", None),
                "info": describe_signer_info(signer_info.countersigner),
            }
        if isinstance(signer_info.countersigner, RFC3161SignedData):
            result["countersigner_nested_rfc3161"] = describe_signed_data(signer_info.countersigner)

    return result


def describe_signed_data(signed_data: SignedData) -> dict[str, Any]:
    """Represent a SignedData as a JSON object."""
    result = {
        "certificates": [format_certificate(cert) for cert in signed_data.certificates],
        "signer": describe_signer_info(signed_data.signer_info),
        "digest_algorithm": signed_data.digest_algorithm.__name__,
        "content_type": signed_data.content_type,
    }

    if isinstance(signed_data, AuthenticodeSignedData) and signed_data.indirect_data:
        indirect: dict[str, Any] = {
            "digest_algorithm": signed_data.indirect_data.digest_algorithm.__name__,
            "digest": signed_data.indirect_data.digest.hex(),
            "content_type": signed_data.indirect_data.content_type,
        }
        pe_image_data = signed_data.indirect_data.content
        if pe_image_data:
            pe_data: dict[str, Any] = {
                "flags": pe_image_data.flags,
                "file_link_type": pe_image_data.file_link_type,
            }
            if pe_image_data.file_link_type == "moniker":
                pe_data["class_id"] = pe_image_data.class_id
                pe_data["content_types"] = pe_image_data.content_types
            else:
                pe_data["publisher"] = pe_image_data.publisher
            indirect["pe_image_data"] = pe_data
        result["indirect_data"] = indirect

    if isinstance(signed_data, RFC3161SignedData) and signed_data.tst_info:
        result["tst_info"] = {
            "hash_algorithm": signed_data.tst_info.hash_algorithm.__name__,
            "digest": signed_data.tst_info.message_digest.hex(),
            "serial_number": str(signed_data.tst_info.serial_number),
            "signing_time": str(signed_data.tst_info.signing_time),
            "signing_time_accuracy": str(signed_data.tst_info.signing_time_accuracy),
            "signing_authority": str(signed_data.tst_info.signing_authority),
        }

    if isinstance(signed_data, AuthenticodeSignedData):
        verify_result, e = signed_data.explain_verify()
        result["verify_result"] = str(verify_result)
        if e:
            result["verify_error"] = str(e)

    return result
