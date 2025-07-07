# Cert-Helper

## Description

Simple wrapper around opnessl crate for creating x509 certificates and keys.
Have some small utility function for reading, saving and validating certificates

The certificate used to sign another certificate need to have CA set to true and Key usage certsign.

## Config

Values that can be selected for building a certificate
| keyword | description | options |
| ----------------- | --------------------------------------------------------------------------- | ----------------------------------- |
| common_name | the common name this certificate shoud have, mandatory field | string: www.foo.se |
| key_type | key type to be used, defaults to RSA2048 | enum: RSA2048, RSA4096, P224, P256, P384, P512 |
| ca | is this certificate used to sign other certificates, default value is false | boolean: true or false |
| country_name | the country code to use,must follow the standard defined by ISO 3166-1 alpha-2. | string: SE |
| organization | organisation name | string: test |
| state_province | some name | string: test |
| locality_time | Stockholm | string: Stockholm |
| alternative_names | list of alternative DNS names this certificate is valid for | string: valid dns names |
| signature_alg | which algorithm to be used for signature, default is SHA256 | senum: SHA1, SHA256, SHA384, SHA512 |
| valid_from | Start date then the certificate is valid, default is now | string: 2010-01-01 |
| valid_to | End date then the certificate is not valid, default is 1 year | string: 2020-01-01 |
| usage | Key usage to ad to the certificates, see list below for options | list of enums, defined in Key Usage table |

### Key usage

If CA is true the key usages to sign certificates and crl lists are added automatically.

| keyword           | description                                                |
| ----------------- | ---------------------------------------------------------- |
| certsign          | allowed to sign certificates                               |
| crlsign           | allowed to sign crl                                        |
| encipherment      | allowed to enciphering private or secret keys              |
| clientauth        | allowed to authenticate as client                          |
| serverauth        | allowed ot be used for server authenthication              |
| signature         | allowed to perfom digital signature (For auth)             |
| contentcommitment | allowed to perfom document signature (prev non repudation) |
