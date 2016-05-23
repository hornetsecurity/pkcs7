{-# LANGUAGE RecordWildCards #-}

{-|
Module: Data.Pkcs7.DigestedData

Data types for digested messages in PKCS#7.
-}
module Data.Pkcs7.DigestedData
    ( DigestAlgorithm(..)
    , DigestAlgorithmIdentifier
    , Digest(..)
    , DigestedData(..)
    ) where

import           Data.ByteString  ( ByteString )

import           Data.Pkcs7.ASN1
import           Data.Pkcs7.Parse
import           Data.Pkcs7.Print

import           Data.Pkcs7.Oids
import           Data.Pkcs7.Types

-- | Message digest algorithms.
data DigestAlgorithm = DigestMD2
                     | DigestMD4
                     | DigestMD5
                     | DigestSHA1
                     | DigestSHA256
                     | DigestSHA384
                     | DigestSHA512
                     | DigestSHA224
                     | DigestUnknown OID
    deriving (Eq, Show)

daTable :: OIDTable DigestAlgorithm
daTable = [ (DigestMD2, oidMD2)
          , (DigestMD4, oidMD4)
          , (DigestMD5, oidMD5)
          , (DigestSHA1, oidSHA1)
          , (DigestSHA256, oidSHA256)
          , (DigestSHA384, oidSHA384)
          , (DigestSHA512, oidSHA512)
          , (DigestSHA224, oidSHA224)
          ]

instance OIDable DigestAlgorithm where
    getObjectID (DigestUnknown oid) = oid
    getObjectID v = toOID daTable v

instance OIDNameable DigestAlgorithm where
    fromObjectID = Just . fromOID DigestUnknown daTable

newtype Digest = Digest ByteString
    deriving (Eq, Show)

-- Digest ::= OCTET STRING
instance ASN1Object Digest where
    toASN1 (Digest bs) = runPrintASN1State printer
      where
        printer = putOctetString bs
    fromASN1 = runParseASN1State parser
      where
        parser = Digest <$> getOctetString

type DigestAlgorithmIdentifier = AlgorithmIdentifier DigestAlgorithm

data DigestedData a =
    DigestedData { digestedVersion   :: Version
                 , digestedAlgorithm :: DigestAlgorithmIdentifier
                 , digestedContent   :: ContentInfo a
                 , digestedDigest    :: Digest
                 }
    deriving (Eq, Show)

instance OIDable (DigestedData a) where
    getObjectID _ = oidDigestedData

-- DigestedData ::= SEQUENCE {
--   version CMSVersion,
--   digestAlgorithm DigestAlgorithmIdentifier,
--   encapContentInfo EncapsulatedContentInfo,
--   digest Digest }
instance ASN1Object a => ASN1Structure (DigestedData a) where
    toASN1Fields DigestedData{..} = runPrintASN1State printer
      where
        printer = putObject digestedVersion
            <> putObject digestedAlgorithm
            <> putObject digestedContent
            <> putObject digestedDigest
    fromASN1Fields = runParseASN1State parser
      where
        parser =
            DigestedData <$> getObject <*> getObject <*> getObject <*> getObject

instance ASN1Object a => ASN1Object (DigestedData a) where
    toASN1 = toASN1Structure Sequence
    fromASN1 = fromASN1Structure Sequence
