{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE RecordWildCards       #-}

{-# LANGUAGE FlexibleInstances     #-}
{-# LANGUAGE MultiParamTypeClasses #-}

{-# OPTIONS_GHC -fno-warn-orphans #-}

module Tests.EnvelopedData ( testEnvelopedData ) where

import           Data.ASN1.BitArray       (toBitArray)
import qualified Data.ASN1.Types          as ASN1
import qualified Data.ByteString          as BS
import           Data.Hourglass           (timeFromElapsed)

import           Test.SmallCheck.Series
import           Test.Tasty
import           Test.Tasty.HUnit
import           Test.Tasty.SmallCheck
import           Tests.Internal

import           Tests.EncryptedData      ()
import           Tests.SignedData         ()
import           Tests.Types              ()

import           Data.Pkcs7.EnvelopedData
import           Data.Pkcs7.Oids          (oidData, oidEnvelopedData)
import           Data.Pkcs7.Types

instance Monad m => Serial m KeyEncryptionAlgorithm where
    series = cons0 KeyEncryptionRSA
             \/ decDepth (KeyEncryptionUnknown <$> oidSeries)

instance Example KeyEncryptionAlgorithm where
    example = KeyEncryptionRSA

instance Monad m => Serial m KeyAgreementAlgorithm where
    series = cons0 KeyAgreementESDH
             \/ cons0 KeyAgreementSSDH
             \/ decDepth (KeyAgreementUnknown <$> oidSeries)

instance Example KeyAgreementAlgorithm where
    example = KeyAgreementESDH

instance Monad m => Serial m KeyWrapAlgorithm where
    series = cons0 KeyWrapDES3
             \/ cons0 KeyWrapRC2
             \/ decDepth (KeyWrapUnknown <$> oidSeries)

instance Example KeyWrapAlgorithm where
    example = KeyWrapDES3

instance Monad m => Serial m KeyDerivationAlgorithm where
    series = cons0 KeyDerivationPBKDF2
             \/ decDepth (KeyDerivationUnknown <$> oidSeries)

instance Example KeyDerivationAlgorithm where
    example = KeyDerivationPBKDF2

instance Monad m => Serial m Originator where
    series = decDepth $ Originator <$> elements [ Nothing, Just [ ], Just [ example ] ]
                                   <~> elements [ Nothing, Just [ ], Just [ example ] ]

instance Example Originator where
    example = Originator (Just [ example ]) (Just [ example ])

instance Monad m => Serial m KeyTransportRecipientIdentifier where
    series = cons1 KeyTransportRecipientIssuerAndSerial
             \/ cons1 KeyTransportRecipientSubjectKeyIdentifier

instance Example KeyTransportRecipientIdentifier where
    example = KeyTransportRecipientIssuerAndSerial example

instance Monad m => Serial m KeyTransport where
    series = decDepth $ KeyTransport <$> pure example
                                     <~> series
                                     <~> series
                                     <~> series

instance Example KeyTransport where
    example = KeyTransport example example example example

instance Monad m => Serial m UserKeyingMaterial where
    series = newtypeCons UserKeyingMaterial

instance Example UserKeyingMaterial where
    example = UserKeyingMaterial "deadbeef"

instance Monad m => Serial m OriginatorPublicKey where
    series = cons2 OriginatorPublicKey

instance Example OriginatorPublicKey where
    example = OriginatorPublicKey example (toBitArray "deadbeef" 64)

instance Monad m => Serial m OriginatorIdentifierOrKey where
    series = cons1 OriginatorIssuerAndSerial
             \/ cons1 OriginatorSubjectKeyIdentifier
             \/ cons1 OriginatorKey

instance Example OriginatorIdentifierOrKey where
    example = OriginatorIssuerAndSerial example

instance Monad m => Serial m KeyAgreementRecipientIdentifier where
    series = cons1 KeyAgreementRecipientIdentifierIssuerAndSerial
             \/ cons1 KeyAgreementRecipientIdentifierKeyIdentifier

instance Example KeyAgreementRecipientIdentifier where
    example = KeyAgreementRecipientIdentifierIssuerAndSerial example

instance Monad m => Serial m RecipientEncryptedKey where
    series = cons2 RecipientEncryptedKey

instance Example RecipientEncryptedKey where
    example = RecipientEncryptedKey example example

instance Monad m => Serial m KeyAgreement where
    series = decDepth $ KeyAgreement <$> pure example
                                     <~> series
                                     <~> series
                                     <~> pure example
                                     <~> elements [ [], [ example ] ]

instance Example KeyAgreement where
    example = KeyAgreement example example Nothing example [ example ]

instance Monad m => Serial m KEKIdentifier where
    series = cons3 KEKIdentifier

instance Example KEKIdentifier where
    example = KEKIdentifier "deadbeef" (Just $ timeFromElapsed 0) Nothing

instance Monad m => Serial m RecipientKeyIdentifier where
    series = cons3 RecipientKeyIdentifier

instance Example RecipientKeyIdentifier where
    example = RecipientKeyIdentifier example Nothing Nothing

instance Serial m a => Serial m (OtherKeyAttribute a) where
    series = decDepth $ OtherKeyAttribute <$> oidSeries <~> series

instance Example a => Example (OtherKeyAttribute a) where
    example = OtherKeyAttribute oidExample Nothing

instance Monad m => Serial m KEK where
    series = decDepth $ KEK <$> pure example
                            <~> pure example
                            <~> series
                            <~> series

instance Example KEK where
    example = KEK example example example example

instance Monad m => Serial m EncryptedKey where
    series = newtypeCons EncryptedKey

instance Example EncryptedKey where
    example = EncryptedKey "deadbeef"

instance Monad m => Serial m Password where
    series = decDepth $ Password <$> pure example
                                 <~> series
                                 <~> series
                                 <~> series

instance Example Password where
    example = Password example (Just example) example example

instance Monad m => Serial m Recipient where
    series = cons1 RecipientKeyTransport
             \/ cons1 RecipientKeyAgreement
             \/ cons1 RecipientKEK
             \/ cons1 RecipientPassword
             \/ decDepth (RecipientOther <$> oidSeries <~> series)

instance Example Recipient where
    example = RecipientKeyTransport example

instance Monad m => Serial m EnvelopedData where
    series = decDepth $ EnvelopedData <$> pure example
                                      <~> series
                                      <~> (cons0 [] \/ cons1 (: []))
                                      <~> pure example
                                      <~> elements [ Nothing, Just [ ], Just [ example ] ]

sampleEnvelopedData :: BS.ByteString
sampleEnvelopedData = BS.concat
                      [ "MIICBQYJKoZIhvcNAQcDoIIB9jCCAfICAQAxggGpMIIBpQIBADCBjDB/MQswCQYDVQQGEwJE"
                      , "RTEPMA0GA1UECAwGQmVybGluMQ8wDQYDVQQHDAZCZXJsaW4xFTATBgNVBAoMDEthbWlrYXpl"
                      , "IEluYzEUMBIGA1UEAwwLRW5ubyBDcmFtZXIxITAfBgkqhkiG9w0BCQEWEmVjcmFtZXJAbWVt"
                      , "ZnJvYi5kZQIJAPD8GbA56arIMA0GCSqGSIb3DQEBAQUABIIBAMNTT8Pmo5ckEXjUWh/3Wl7N"
                      , "340dxmcCGQwp8BbxhoyHOIduI5dfPoDYyv2jzG7fVHWNnYvLQ4aj6hQ9y2hq3/hnz9eHibQj"
                      , "5ws5TgB6ylPtXtiWHamt75WeQ95rrcn90IcW9Pu5dZKwQPcCpHi/2wRHOGhlW9k0OiYewDgM"
                      , "F9EDfVGkqrfuJx8JAcsDfW0C9caWeXNXvuNWNJ3paLcoXyUj6HRw4azZHTb0DC99BEqxMmwJ"
                      , "+sTeTRA+FwDLifs4bKBjlN/z1PcARbeXsM1PC3dDkMIg510GHk1LugvFAIXsmwS2Ds+YNyCj"
                      , "/hTXca0GRczdxH2D90vrxK+S17Fy6OgwQAYJKoZIhvcNAQcBMBEGBSsOAwIHBAjJ0F59S4fa"
                      , "14AgIO+q+Vo67Zq5sk2AxpKryF7uFpOecTLwgn0zh3mnmcs="
                      ]

testEnvelopedData :: TestTree
testEnvelopedData = testGroup "Data.Pkcs7.EnvelopedData"
                    [ testProperty "KeyEncryptionAlgorithm" (propRoundtripOID :: KeyEncryptionAlgorithm -> Bool)
                    , testProperty "KeyDerivationAlgorithm" (propRoundtripOID :: KeyDerivationAlgorithm -> Bool)
                    , testProperty "Originator" (propRoundtripASN1 :: Originator -> Bool)
                    , testProperty "KeyTransportRecipientIdentifier" (propRoundtripASN1 :: KeyTransportRecipientIdentifier -> Bool)
                    , testProperty "KeyTransport" (propRoundtripASN1 :: KeyTransport -> Bool)
                    , testProperty "OriginatorPublicKey" (propRoundtripASN1 :: OriginatorPublicKey -> Bool)
                    , testProperty "OriginatorIdentifierOrKey" (propRoundtripASN1 :: OriginatorIdentifierOrKey -> Bool)
                    , testProperty "UserKeyingMaterial" (propRoundtripASN1 :: UserKeyingMaterial -> Bool)
                    , testProperty "KeyAgreementRecipientIdentifier" (propRoundtripASN1 :: KeyAgreementRecipientIdentifier -> Bool)
                    , testProperty "RecipientEncryptedKey" (propRoundtripASN1 :: RecipientEncryptedKey -> Bool)
                    , testProperty "KeyAgreement" (propRoundtripASN1 :: KeyAgreement -> Bool)
                    , testProperty "KEKIdentifier" (propRoundtripASN1 :: KEKIdentifier -> Bool)
                    , testProperty "RecipientKeyIdentifier" (propRoundtripASN1 :: RecipientKeyIdentifier -> Bool)
                    , testProperty "OtherKeyAttribute" (propRoundtripASN1 :: OtherKeyAttribute Data -> Bool)
                    , testProperty "KEK" (propRoundtripASN1 :: KEK -> Bool)
                    , testProperty "EncryptedKey" (propRoundtripASN1 :: EncryptedKey -> Bool)
                    , testProperty "Password" (propRoundtripASN1 :: Password -> Bool)
                    , testProperty "Recipient" (propRoundtripASN1 :: Recipient -> Bool)
                    , testProperty "EnvelopedData" (propRoundtripASN1 :: EnvelopedData -> Bool)
                    , testCase "EnvelopedData Sample" $
                      case decodeDER sampleEnvelopedData of
                        Left e -> assertFailure e
                        Right ci ->
                            case contentContent ci of
                              Nothing -> assertFailure "EnvelopedData value is missing"
                              Just EnvelopedData{..} -> do
                                contentContentType ci @?= ContentType oidEnvelopedData

                                envelopedVersion @?= Version 0
                                envelopedOriginator @?= Nothing
                                length envelopedRecipients @?= 1
                                envelopedUnprotectedAttributes @?= Nothing

                                let EncryptedContent{..} = envelopedEncryptedContent
                                encryptedContentType @?= ContentType oidData
                                algorithm encryptedContentEncryptionAlgorithm @?= ContentEncryptionDESCBC

                                case algorithmParameters encryptedContentEncryptionAlgorithm of
                                  Just (Any [ASN1.OctetString bs]) -> BS.length bs @?= 8
                                  _ -> assertFailure "Invalid DES-CBC algorithm parameters"
                    ]
