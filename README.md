# Haskell PKCS #7 Library

This library provides data structures and functions to represent,
read, and write objects defined by PKCS #7 (RFC2315) and Cryptographic
Message Syntax (RFC2630).

If your're interested in an exciting career with Haskell have a look at our career page:

https://www.hornetsecurity.com/de/karriere


# Usage

PKCS #7 and CMS are based on ASN.1.  This library uses the
`Data.ASN1.Types.ASN1Object` class of the **asn1-types** library to
read and write objects, meaning you will the `fromASN1` and `toASN1`
to convert between ASN1 and PKCS #7 objects.  To read and write ASN1
sequences, use the functionality of `Data.ASN1.Encoding` in the
**asn1-encoding** library.

```haskell
import Data.ByteString         (ByteString)
import Data.ASN1.Types         (fromASN1)
import Data.ASN1.Encoding      (decodeASN1', DER)
import Data.Pkcs7.Types        (contentContent)
import Data.Pkcs7.DigestedData (digestedContent)

extract :: ByteString -> ByteString
extract input = data
    where (Right asn1) = decodeASN1' DER input
          (object, _) = fromASN1 asn1
          (Data data) = contentContent $ digestedContent object
```

Some data structures, such as `ContentInfo` or `Attribute`, can be
parameterized with a custom data type.  You can use the `Any` type
leave the field unrestricted and retain the original ASN1 encoding.
Other common parameter types are `Data` for encapsulated binary data
and `None` if the specification requires the field to not contain a
value.
