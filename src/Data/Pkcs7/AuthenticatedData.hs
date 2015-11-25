{-# LANGUAGE RecordWildCards #-}

{-|
Module: Data.Pkcs7.AuthenticatedData

Data types for data with message authentication codes in PKCS#7.
-}
module Data.Pkcs7.AuthenticatedData
    ( MessageAuthenticationCodeAlgorithm(..)
    , MessageAuthenticationCodeAlgorithmIdentifier
    , MessageAuthenticationCode(..)
    , AuthenticatedData(..)
    ) where

import           Data.ByteArray           (constEq)
import           Data.ByteString          (ByteString)

import           Data.Pkcs7.ASN1
import           Data.Pkcs7.Parse
import           Data.Pkcs7.Print

import           Data.Pkcs7.Oids
import           Data.Pkcs7.Types

import           Data.Pkcs7.EnvelopedData (Originator (..), Recipient (..))
import           Data.Pkcs7.SignedData    (DigestAlgorithmIdentifier)

data MessageAuthenticationCodeAlgorithm = MessageAuthenticationCodeHMACSHA1
                                        | MessageAuthenticationCodeUnknown OID
                                          deriving (Eq, Show)

maaTable :: OIDTable MessageAuthenticationCodeAlgorithm
maaTable = [ (MessageAuthenticationCodeHMACSHA1, oidHMACSHA1)
           ]

instance OIDable MessageAuthenticationCodeAlgorithm where
    getObjectID (MessageAuthenticationCodeUnknown oid) = oid
    getObjectID v = toOID maaTable v

instance OIDNameable MessageAuthenticationCodeAlgorithm where
    fromObjectID = Just . fromOID MessageAuthenticationCodeUnknown maaTable

type MessageAuthenticationCodeAlgorithmIdentifier = AlgorithmIdentifier MessageAuthenticationCodeAlgorithm

-- | Message authentication codes.
newtype MessageAuthenticationCode = MessageAuthenticationCode ByteString
    deriving Show

instance Eq MessageAuthenticationCode where
    (MessageAuthenticationCode left) == (MessageAuthenticationCode right) = left `constEq` right

-- MessageAuthenticationCode ::= OCTET STRING
instance ASN1Object MessageAuthenticationCode where
    toASN1 (MessageAuthenticationCode bs) = runPrintASN1State printer
        where printer = putOctetString bs
    fromASN1 = runParseASN1State parser
        where parser = MessageAuthenticationCode <$> getOctetString

data AuthenticatedData a = AuthenticatedData { authenticatedVersion          :: Version
                                             , authenticatedOriginator       :: Maybe Originator
                                             , authenticatedRecipients       :: [Recipient]
                                             , authenticatedMacAlgorithm     :: MessageAuthenticationCodeAlgorithmIdentifier
                                             , authenticatedDigestAlgorithm  :: Maybe DigestAlgorithmIdentifier
                                             , authenticatedContent          :: ContentInfo a
                                             , authenticatedAuthAttributes   :: Maybe [Attribute Any]
                                             , authenticatedMac              :: MessageAuthenticationCode
                                             , authenticatedUnauthAttributes :: Maybe [Attribute Any]
                                             } deriving (Eq, Show)

-- AuthenticatedData ::= SEQUENCE {
--   version CMSVersion,
--   originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
--   recipientInfos RecipientInfos,
--   macAlgorithm MessageAuthenticationCodeAlgorithm,
--   digestAlgorithm [1] DigestAlgorithmIdentifier OPTIONAL,
--   encapContentInfo EncapsulatedContentInfo,
--   authAttrs [2] IMPLICIT AuthAttributes OPTIONAL,
--   mac MessageAuthenticationCode,
--   unauthAttrs [3] IMPLICIT UnauthAttributes OPTIONAL }
--
-- RecipientInfos ::= SET SIZE (1..MAX) OF RecipientInfo
--
-- AuthAttributes ::= SET SIZE (1..MAX) OF Attribute
--
-- UnauthAttributes ::= SET SIZE (1..MAX) OF Attribute
instance ASN1Object a => ASN1Structure (AuthenticatedData a) where
    toASN1Fields AuthenticatedData{..} = runPrintASN1State printer
        where printer = putObject authenticatedVersion
                        <> putImplicitMaybe 0 authenticatedOriginator
                        <> putSetOf authenticatedRecipients
                        <> putObject authenticatedMacAlgorithm
                        <> putImplicitMaybe 1 authenticatedDigestAlgorithm
                        <> putObject authenticatedContent
                        <> putImplicitMaybe 2 (SetOf <$> authenticatedAuthAttributes)
                        <> putObject authenticatedMac
                        <> putImplicitMaybe 3 (SetOf <$> authenticatedUnauthAttributes)
    fromASN1Fields = runParseASN1State parser
        where parser = AuthenticatedData <$> getObject
                                         <*> getImplicitMaybe 0
                                         <*> getSetOf
                                         <*> getObject
                                         <*> getImplicitMaybe 1
                                         <*> getObject
                                         <*> (fmap unSetOf <$> getImplicitMaybe 2)
                                         <*> getObject
                                         <*> (fmap unSetOf <$> getImplicitMaybe 3)

instance ASN1Object a => ASN1Object (AuthenticatedData a) where
    toASN1 = toASN1Structure Sequence
    fromASN1 = fromASN1Structure Sequence
