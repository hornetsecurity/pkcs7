{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE RecordWildCards       #-}

{-# LANGUAGE FlexibleInstances     #-}
{-# LANGUAGE MultiParamTypeClasses #-}

{-# OPTIONS_GHC -fno-warn-orphans #-}

module Tests.SignedData ( testSignedData ) where

import           Data.ASN1.BitArray     (toBitArray)
import qualified Data.ASN1.Types        as ASN1
import qualified Data.ByteString        as BS

import           Test.SmallCheck.Series
import           Test.Tasty
import           Test.Tasty.HUnit
import           Test.Tasty.SmallCheck
import           Tests.Internal

import           Tests.DigestedData     ()
import           Tests.Types            ()

import           Data.Pkcs7.Oids        (oidSignedData)
import           Data.Pkcs7.SignedData
import           Data.Pkcs7.Types

instance Monad m => Serial m SignatureAlgorithm where
    series = cons0 SignatureDSA
             \/ cons0 SignatureSHA1WithDSA
             \/ cons0 SignatureRSA
             \/ cons0 SignatureMD2WithRSA
             \/ cons0 SignatureMD4WithRSA
             \/ cons0 SignatureMD5WithRSA
             \/ cons0 SignatureSHA1WithRSA
             \/ cons0 SignatureSHA256WithRSA
             \/ cons0 SignatureSHA384WithRSA
             \/ cons0 SignatureSHA512WithRSA
             \/ cons0 SignatureSHA224WithRSA
             \/ decDepth (SignatureUnknown <$> oidSeries)

instance Example SignatureAlgorithm where
    example = SignatureRSA

instance Monad m => Serial m Signature where
    series = newtypeCons Signature

instance Example Signature where
    example = Signature "deadbeef"

instance Monad m => Serial m ExtendedCertificate where
    series = decDepth $ ExtendedCertificate <$> pure example
                                            <~> pure example
                                            <~> elements [ [], [ example ] ]

instance Example ExtendedCertificate where
    example = ExtendedCertificate example example []

instance Serial m a => Serial m (Signed a) where
    series = cons3 Signed

instance Example a => Example (Signed a) where
    example = Signed example example (toBitArray "deadbeef" 64)

instance Monad m => Serial m CertificateChoice where
    series = cons0 (CertificateCertificate example)
             \/ cons1 CertificateExtended
             \/ cons1 CertificateAttributeCertificateV1
             \/ cons1 CertificateAttributeCertificateV2
             \/ decDepth (CertificateOther <$> oidSeries <~> series)

instance Example CertificateChoice where
    example = CertificateCertificate example

instance Monad m => Serial m RevocationChoice where
    series = cons1 RevocationCRL \/ decDepth (RevocationOther <$> oidSeries <~> series)

instance Example RevocationChoice where
    example = RevocationOther oidExample example

instance Monad m => Serial m SubjectKeyIdentifier where
    series = newtypeCons SubjectKeyIdentifier

instance Example SubjectKeyIdentifier where
    example = SubjectKeyIdentifier "deadbeef"

instance Monad m => Serial m SignerIdentifier where
    series = cons1 SignerIssuerAndSerial \/ cons1 SignerSubjectKeyIdentifier

instance Example SignerIdentifier where
    example = SignerSubjectKeyIdentifier example

instance Monad m => Serial m Signer where
    series = decDepth $ Signer <$> pure example
                               <~> pure example
                               <~> pure example
                               <~> elements [ Nothing, Just [], Just [ example ] ]
                               <~> pure example
                               <~> series
                               <~> elements [ Nothing, Just [], Just [ example ] ]

instance Example Signer where
    example = Signer{..}
        where signerVersion = example
              signerIdentifier = example
              signerDigestAlgorithm = example
              signerAuthenticatedAttributes = Nothing
              signerSignatureAlgorithm = example
              signerSignature = example
              signerUnauthenticatedAttributes = Nothing

instance Serial m a => Serial m (SignedData a) where
    series = decDepth $ SignedData <$> pure example
                                   <~> elements [ [], [ example ] ]
                                   <~> series
                                   <~> elements [ Nothing, Just [], Just [ example ] ]
                                   <~> elements [ Nothing, Just [], Just [ example ] ]
                                   <~> elements [ [], [ example ], [ example, example ] ]

sampleSignedData :: BS.ByteString
sampleSignedData = BS.concat
                   [ "MIIGlQYJKoZIhvcNAQcCoIIGhjCCBoICAQExCzAJBgUrDgMCGgUAMCsGCSqGSIb3DQEHAaAe"
                   , "BBxMb3JlbSBJcHN1bSBEb2xvciBBbWV0IFNpdCEKoIIDfjCCA3owggJiAgkA8PwZsDnpqsgw"
                   , "DQYJKoZIhvcNAQELBQAwfzELMAkGA1UEBhMCREUxDzANBgNVBAgMBkJlcmxpbjEPMA0GA1UE"
                   , "BwwGQmVybGluMRUwEwYDVQQKDAxLYW1pa2F6ZSBJbmMxFDASBgNVBAMMC0Vubm8gQ3JhbWVy"
                   , "MSEwHwYJKoZIhvcNAQkBFhJlY3JhbWVyQG1lbWZyb2IuZGUwHhcNMTUxMTEzMTgzNjAwWhcN"
                   , "MTUxMjEzMTgzNjAwWjB/MQswCQYDVQQGEwJERTEPMA0GA1UECAwGQmVybGluMQ8wDQYDVQQH"
                   , "DAZCZXJsaW4xFTATBgNVBAoMDEthbWlrYXplIEluYzEUMBIGA1UEAwwLRW5ubyBDcmFtZXIx"
                   , "ITAfBgkqhkiG9w0BCQEWEmVjcmFtZXJAbWVtZnJvYi5kZTCCASIwDQYJKoZIhvcNAQEBBQAD"
                   , "ggEPADCCAQoCggEBANWMxFaCHrcdF1csXIFB3SvGbbaEY/GBxORPeRCz+LXjc0Osan5VFip7"
                   , "gZhn3Hfrhrdvwn9aObpS4NuzJoG+24baNpkpC5JZSYusKt/st7V6zCc6jqjAESKAAM4yyq3Q"
                   , "jCzcKszZDYqGvOOeBlruVUxe16HdT+Xfy4br8tZLh5idD+u46nbOi52Hb2odsdWYBnVq5q/H"
                   , "qn4GNB/d6/tRwHpgOSXdUtHjVWa1SGSHJTIr1KN6t+04DxPv6QZrqWKnIQ1gMbB16d2YjWjc"
                   , "FZmJw5VRHgK5c1Ucf4jyG31J10XBLfpGnmT2F1qDxLUvM9RwGARbYdGW5oRPflWL9HjPeJ0C"
                   , "AwEAATANBgkqhkiG9w0BAQsFAAOCAQEARoCXbs24LaU4AlpI23q9+VuTbIoLyhtsIZXxD5HY"
                   , "SWfnZ7oaDsCZA2E7rt/fPTc4KFyiasrWj1qd+ih04xP1tpSq4kyNjkkeB79LbBhZEfHjRQEU"
                   , "bobOHksdY/6L5SOkkxFXeLHCFMth4osksaDd5zwojjP46zdzTrEzsdLdKX9OyHeHjKIElKyj"
                   , "8hGEgWlyXZR8G7nZ4/gvz3XZ1d+lkqUR+z6mfh/2adDAc68Jw89Q8wzPa3W/0sNu5OV1Zc0S"
                   , "cMNBy/TNR1zOriS3E8LQYuQ5+34IwpvLU0rTZxS0uljgR1abye/DVBbMzujK+P1SCNJODHds"
                   , "CAT+mWabke1dOTGCAr8wggK7AgEBMIGMMH8xCzAJBgNVBAYTAkRFMQ8wDQYDVQQIDAZCZXJs"
                   , "aW4xDzANBgNVBAcMBkJlcmxpbjEVMBMGA1UECgwMS2FtaWthemUgSW5jMRQwEgYDVQQDDAtF"
                   , "bm5vIENyYW1lcjEhMB8GCSqGSIb3DQEJARYSZWNyYW1lckBtZW1mcm9iLmRlAgkA8PwZsDnp"
                   , "qsgwCQYFKw4DAhoFAKCCAQcwGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0B"
                   , "CQUxDxcNMTUxMTE4MTA0ODQxWjAjBgkqhkiG9w0BCQQxFgQUSOxBWucaxT4jvCVdRcxRcd2u"
                   , "JlswgacGCSqGSIb3DQEJDzGBmTCBljALBglghkgBZQMEASowCAYGKoUDAgIJMAoGCCqFAwcB"
                   , "AQICMAoGCCqFAwcBAQIDMAgGBiqFAwICFTALBglghkgBZQMEARYwCwYJYIZIAWUDBAECMAoG"
                   , "CCqGSIb3DQMHMA4GCCqGSIb3DQMCAgIAgDANBggqhkiG9w0DAgIBQDAHBgUrDgMCBzANBggq"
                   , "hkiG9w0DAgIBKDANBgkqhkiG9w0BAQEFAASCAQChVg5RBet6wiRmY+wRdscg8LLsspwq8f0r"
                   , "zl9nlGn/vpmYu57DL8aSWfy/cFK9eoOgU+ADTDgeMwd0O8QbLQvz7gc5GSJe3FrPd29+3MDB"
                   , "eFEF8eLEQuy6MfX7uyPwoVS8/YZLG/h/MOyhaNH7JfUozI1AeT4g2ygh2DMXuGeRntTR9WdJ"
                   , "dIyRspE7Rj/t1XdlOhyljnKO87Unr6o4+FTCiTZotvRGGtVa2NlbqwBoDxnpwhCAHXf4R/+w"
                   , "lRhzljRUH69IFxkwTNgEq9oObRqoL6BLt9UtI42rjnJqHUlB07PLXhsTn+59C5EuOChU8zkN"
                   , "H26qCXvK8rBrszm62PA/"
                   ]

testSignedData :: TestTree
testSignedData = testGroup "Data.Pkcs7.SignedData"
                 [ testProperty "SignatureAlgorithm" (propRoundtripOID :: SignatureAlgorithm -> Bool)
                 , testProperty "Signature" (propRoundtripASN1 :: Signature -> Bool)
                 , testProperty "ExtendedCertificate" (propRoundtripASN1 :: ExtendedCertificate -> Bool)
                 , testProperty "Signed" (propRoundtripASN1 :: Signed Data -> Bool)
                 , testProperty "CertificateChoice" (propRoundtripASN1 :: CertificateChoice -> Bool)
                 , testProperty "RevocationChoice" (propRoundtripASN1 :: RevocationChoice -> Bool)
                 , testProperty "SubjectKeyIdentifier" (propRoundtripASN1 :: SubjectKeyIdentifier -> Bool)
                 , testProperty "SignerIdentifier" (propRoundtripASN1 :: SignerIdentifier -> Bool)
                 , testProperty "Signer" (propRoundtripASN1 :: Signer -> Bool)
                 , testProperty "SignedData" (propRoundtripASN1 :: SignedData Data -> Bool)
                 , testCase "SingedData Sample" $
                     case decodeDER sampleSignedData of
                       Left e -> assertFailure e
                       Right ci ->
                           case contentContent ci of
                             Nothing -> assertFailure "SignedData value is missing"
                             Just SignedData{..} -> do
                               contentContentType ci @?= ContentType oidSignedData

                               signedVersion @?= Version 1
                               signedDigestAlgorithms @?= [ AlgorithmIdentifier DigestSHA1 (Just (Any [ASN1.Null])) ]
                               contentContent signedContentInfo @?= Just (Any [ ASN1.OctetString "Lorem Ipsum Dolor Amet Sit!\n" ])

                               (length <$> signedCertificates) @?= Just 1
                               signedCrls @?= Nothing

                               length signedSigners @?= 1

                               let Signer{..} = head signedSigners
                               signerVersion @?= Version 1
                               signerDigestAlgorithm @?= AlgorithmIdentifier DigestSHA1 (Just (Any [ASN1.Null]))
                               signerSignatureAlgorithm @?= AlgorithmIdentifier SignatureRSA (Just (Any [ASN1.Null]))
                   ]



