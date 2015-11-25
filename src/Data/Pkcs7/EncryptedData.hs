{-# LANGUAGE RecordWildCards #-}

{-|
Module: Data.Pkcs7.EncryptedData

Data types for encrypted data in PKCS#7.
-}
module Data.Pkcs7.EncryptedData
    ( ContentEncryptionAlgorithm(..)
    , ContentEncryptionAlgorithmIdentifier
    , EncryptedContent(..)
    , EncryptedData(..)
    ) where

import           Data.Pkcs7.ASN1
import           Data.Pkcs7.Parse
import           Data.Pkcs7.Print

import           Data.Pkcs7.Oids
import           Data.Pkcs7.Types

-- | Symmetric content encryption algorithms.
data ContentEncryptionAlgorithm = ContentEncryptionDESCBC
                                | ContentEncryptionDESEDE3CBC
                                | ContentEncryptionRC2
                                | ContentEncryptionAES128CBC
                                | ContentEncryptionAES192CBC
                                | ContentEncryptionAES256CBC
                                | ContentEncryptionAES128CCM
                                | ContentEncryptionAES192CCM
                                | ContentEncryptionAES256CCM
                                | ContentEncryptionAES128GCM
                                | ContentEncryptionAES192GCM
                                | ContentEncryptionAES256GCM
                                | ContentEncryptionUnknown OID
                                  deriving (Eq, Show)

ceaTable :: OIDTable ContentEncryptionAlgorithm
ceaTable = [ (ContentEncryptionDESCBC, oidDESCBC)
           , (ContentEncryptionDESEDE3CBC, oidDESEDE3CBC)
           , (ContentEncryptionRC2, oidRC2)
           , (ContentEncryptionAES128CBC, oidAES128CBC)
           , (ContentEncryptionAES192CBC, oidAES192CBC)
           , (ContentEncryptionAES256CBC, oidAES256CBC)
           , (ContentEncryptionAES128CCM, oidAES128CCM)
           , (ContentEncryptionAES192CCM, oidAES192CCM)
           , (ContentEncryptionAES256CCM, oidAES256CCM)
           , (ContentEncryptionAES128GCM, oidAES128GCM)
           , (ContentEncryptionAES192GCM, oidAES192GCM)
           , (ContentEncryptionAES256GCM, oidAES256GCM)
           ]

instance OIDable ContentEncryptionAlgorithm where
    getObjectID (ContentEncryptionUnknown oid) = oid
    getObjectID v = toOID ceaTable v

instance OIDNameable ContentEncryptionAlgorithm where
    fromObjectID = Just . fromOID ContentEncryptionUnknown ceaTable

type ContentEncryptionAlgorithmIdentifier = AlgorithmIdentifier ContentEncryptionAlgorithm

data EncryptedContent = EncryptedContent { encryptedContentType                :: ContentType
                                         , encryptedContentEncryptionAlgorithm :: ContentEncryptionAlgorithmIdentifier
                                         , encryptedContentContent             :: Maybe Data
                                         }  deriving (Eq, Show)

-- EncryptedContentInfo ::= SEQUENCE {
--   contentType ContentType,
--   contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
--   encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL }
--
-- EncryptedContent ::= OCTET STRING
instance ASN1Structure EncryptedContent where
    toASN1Fields EncryptedContent{..} = runPrintASN1State printer
        where printer = putObject encryptedContentType
                        <> putObject encryptedContentEncryptionAlgorithm
                        <> putMaybe (putNext . fromEncryptedContent <$> encryptedContentContent)
              fromEncryptedContent (Data bs) = Other Context 0 bs
    fromASN1Fields = runParseASN1State parser
        where parser = EncryptedContent <$> getObject
                                        <*> getObject
                                        <*> getNextMaybe toEncryptedContent
              toEncryptedContent (Other Context 0 bs) = Just (Data bs)
              toEncryptedContent _ = Nothing

instance ASN1Object EncryptedContent where
    toASN1 = toASN1Structure Sequence
    fromASN1 = fromASN1Structure Sequence

data EncryptedData = EncryptedData { encryptedVersion               :: Version
                                   , encryptedContent               :: EncryptedContent
                                   , encryptedUnprotectedAttributes :: Maybe [Attribute Any]
                                   } deriving (Eq, Show)

instance OIDable EncryptedData where
    getObjectID _ = oidEncryptedData

-- EncryptedData ::= SEQUENCE {
--   version CMSVersion,
--   encryptedContentInfo EncryptedContentInfo,
--   unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }
instance ASN1Structure EncryptedData where
    toASN1Fields EncryptedData{..} = runPrintASN1State printer
        where printer = putObject encryptedVersion
                        <> putObject encryptedContent
                        <> putImplicitMaybe 0 (SetOf <$> encryptedUnprotectedAttributes)
    fromASN1Fields = runParseASN1State parser
        where parser = EncryptedData <$> getObject
                                     <*> getObject
                                     <*> (fmap unSetOf <$> getImplicitMaybe 0)

instance ASN1Object EncryptedData where
    toASN1 = toASN1Structure Sequence
    fromASN1 = fromASN1Structure Sequence
