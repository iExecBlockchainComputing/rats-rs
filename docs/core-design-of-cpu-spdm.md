# CPU-TEE SPDM Message Content Design

This document introduces the core design ideas of the SPDM secure session layer part of the rats-rs project, namely the integration of SPDM and TEE Attestation.

## X.509 Certificate Generation for CPU-TEE

The X.509 certificates in this project adopt an overall first-level self-signed certificate design. The Evidence and Endorsements of the TEE instance are embedded in the extension fields of the certificate.

The specific process of certificate generation is:

1. Generate a pair of asymmetric keys (called pubkey, privkey) within the TEE instance, with the private key part retained within the TEE.

2. Construct a Custom claims list, which includes a field named "pubkey-hash" with the value being the hash value of pubkey. The remaining fields are key-value pair data that can be arbitrarily filled by upper-level applications.

3. Encode the Custom claims list data in CBOR format into binary data and calculate its Hash value.

4. Use the Hash value from step 3 as User-Data, call the remote attestation primitive layer logic to generate Evidence (such as Quote in SGX).

5. Call the remote attestation primitive layer logic to obtain the Endorsements corresponding to the Evidence (such as Collateral in SGX).

6. Package Tagged Evidence and Endorsements Manifest, serialize them into CBOR binary data respectively, and place them in the corresponding certificate extension fields.

7. Generate the SubjectPublickeyInfo field of the certificate based on pubkey.

8. Sign the certificate with pubkey.

![Complete process diagram](./rats-rs-x509-cert.svg)

The file [demo-sgx-cert.pem](demo-sgx-cert.pem) is an example of a certificate generated during the process of establishing an SPDM secure session using rats-rs on an SGX instance.

## CPU-TEE Measurements Message Content Customization

Measurements are essentially descriptions of the current TEE environment state. In the SPDM protocol, the Requester can check the state of the peer TEE environment by sending GET_MEASUREMENTS messages.

The Measurements defined in SPDM messages are represented in Block form, with each Block identified by a Measurement Index. The Index value ranges from 0x00-0xFE. Among them, there is a special Block numbered 0xFD, and the data stored in the corresponding Block represents the Measurement manifest. Generally speaking, the Measurement manifest records the Index of all Measurements on the device and the meaning of the corresponding measurement content; or directly describes the values of all Measurements on the device in list form.

This project defines a Measurement Block for CPU-TEE, and its related attribute information is as follows:

```txt
Index = 0xFD
DMTFSpecMeasurementValueType[6:0] = 0x04 (Freeform measurement manifest)
```

The data stored in this Measurement Block is the Claims parsed from Evidence formatted in CBOR form.

The following figure shows the Measurement Block construction process using SGX-type TEE as an example:

![MEASUREMENTS message](./rats-rs-measurements.svg)

The process of checking Measurements is as follows:

1. During inspection, the Requester first sends a GET_MEASUREMENTS message, carrying the target query Index as 0xFD.

2. After receiving the request, the Responder checks the target Index and calls the remote attestation primitive layer to obtain the current instance's Evidence data, then parses it into Claims, constructs Measurement Data, and then constructs a MEASUREMENTS message to return to the Requester.

3. The Requester deserializes the Measurement Data into Claims and compares it with the reference values provided by the upper-level user to decide whether to establish a session.
