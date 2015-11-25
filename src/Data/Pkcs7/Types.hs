{-# LANGUAGE RecordWildCards #-}

{-|
Module: Data.Pkcs7.Types

Data types shared by the different modules in Data.Pkcs7.
-}
module Data.Pkcs7.Types
    ( Data(..)
    , None(..)
    , Any(..)
    , Version(..)
    , ContentType(..)
    , ContentInfo(..)
    , AlgorithmIdentifier(..)
    , Attribute(..)
    , IssuerAndSerial(..)
    , Certificate(..)
    , CRL(..)
    ) where

import           Control.Arrow    (first)

import           Data.ByteString  (ByteString)

import           Data.ASN1.Stream (getConstructedEnd)
import           Data.Pkcs7.ASN1
import           Data.Pkcs7.Parse
import           Data.Pkcs7.Print

import           Data.Pkcs7.Oids  (oidData)

import qualified Data.X509        (CRL, Certificate, DistinguishedName)

-- | ByteString wrapper for arbitrary content data
data Data = Data ByteString
            deriving (Eq, Show)

instance OIDable Data where
    getObjectID _ = oidData

-- Data ::= OCTET STRING
instance ASN1Object Data where
    toASN1 (Data bs) = runPrintASN1State printer
        where printer = putOctetString bs
    fromASN1 = runParseASN1State parser
        where parser = Data <$> getOctetString

-- | Null object for use as parameter to AlgorithmIdentifier when no
-- parameters are expected.
data None = None
            deriving (Eq, Show)

instance ASN1Object None where
    toASN1 _ = (:) Null
    fromASN1 (Null:s) = Right (None, s)
    fromASN1 _ = Left "Null expected"

-- | Encode/decode ASN.1 ANY fields without knowing the actual type.
-- Extract the next element or SEQUENCE from the ASN.1 stream.
data Any = Any [ASN1]
         deriving (Eq, Show)

instance ASN1Object Any where
    toASN1 (Any l) = (l ++)
    fromASN1 (Start t:xs) = let (s, xs') = getConstructedEnd 0 xs in
                            Right (Any (Start t : (s ++ [End t])), xs')
    fromASN1 (x:xs) = Right (Any [x], xs)
    fromASN1 [] = Right (Any [], [])

-- | Version identifier for various structures
data Version = Version Integer
               deriving (Eq, Show)

-- Version ::= INTEGER
instance ASN1Object Version where
    toASN1 (Version n) = runPrintASN1State printer
        where printer = putIntVal n
    fromASN1 = runParseASN1State parser
        where parser = Version <$> getIntVal

-- | ContentType identifier for various structures
data ContentType = ContentType OID
                   deriving (Eq, Show)

-- ContentType ::= OBJECT IDENTIFIER
instance ASN1Object ContentType where
    toASN1 (ContentType oid) = runPrintASN1State printer
        where printer = putOID oid
    fromASN1 = runParseASN1State parser
        where parser = ContentType <$> getOID

-- | Generic encapsulation for data with content-type
data ContentInfo a = ContentInfo { contentContentType :: ContentType
                                 , contentContent     :: Maybe a
                                 } deriving (Eq, Show)

-- id-ct-contentInfo OBJECT IDENTIFIER ::= { iso(1) member-body(2)
--   us(840) rsadsi(113549) pkcs(1) pkcs9(9) smime(16) ct(1) 6 }
instance OIDable (ContentInfo a) where
    getObjectID _ = [ 1, 2, 840, 113549, 1, 9, 16, 1, 6 ]

-- ContentInfo ::= SEQUENCE {
--   contentType ContentType,
--   content [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL }
instance ASN1Object a => ASN1Structure (ContentInfo a) where
    toASN1Fields ContentInfo{..} = runPrintASN1State printer
        where printer = putObject contentContentType
                         <> putExplicitMaybe 0 contentContent
    fromASN1Fields = runParseASN1State parser
        where parser = ContentInfo <$> getObject
                                   <*> getExplicitMaybe 0

instance ASN1Object a => ASN1Object (ContentInfo a) where
    toASN1 = toASN1Structure Sequence
    fromASN1 = fromASN1Structure Sequence

-- | Generic algorithm identifier for digest, signature, key
-- encryption, content encryption, message authentication, and key
-- derivation.
data AlgorithmIdentifier a = AlgorithmIdentifier { algorithm           :: a
                                                 , algorithmParameters :: Maybe Any
                                                 } deriving (Eq, Show)

-- AlgorithmIdentifier  ::=  SEQUENCE {
--   algorithm OBJECT IDENTIFIER,
--   parameters ANY DEFINED BY algorithm OPTIONAL }
instance (OIDable a, OIDNameable a) => ASN1Structure (AlgorithmIdentifier a) where
    toASN1Fields AlgorithmIdentifier{..} = runPrintASN1State printer
        where printer = putOID (getObjectID algorithm)
                        <> putObjectMaybe algorithmParameters
    fromASN1Fields = runParseASN1State parser
        where parser = AlgorithmIdentifier <$> (maybe (throwParseError "invalid object id") return . fromObjectID =<< getOID)
                                           <*> getObjectMaybe

instance (OIDable a, OIDNameable a) => ASN1Object (AlgorithmIdentifier a) where
    toASN1 = toASN1Structure Sequence
    fromASN1 = fromASN1Structure Sequence

-- | Attributes from X.501 and X.509
data Attribute a = Attribute { attributeType   :: OID
                             , attributeValues :: [a]
                             } deriving (Eq, Show)

-- Attribute ::= SEQUENCE {
--   attrType OBJECT IDENTIFIER,
--   attrValues SET OF AttributeValue }
--
-- AttributeValue ::= ANY
instance ASN1Object a => ASN1Structure (Attribute a) where
    toASN1Fields Attribute{..} = runPrintASN1State printer
        where printer = putOID attributeType
                        <> putObject (SetOf attributeValues)
    fromASN1Fields = runParseASN1State parser
        where parser = Attribute <$> getOID
                                 <*> (unSetOf <$> getObject)

instance ASN1Object a => ASN1Object (Attribute a) where
    toASN1 = toASN1Structure Sequence
    fromASN1 = fromASN1Structure Sequence

-- | Identifying a signer via the certificate issuer and serial number.
data IssuerAndSerial = IssuerAndSerial { issuerName   :: Data.X509.DistinguishedName
                                       , issuerSerial :: Integer
                                       } deriving (Eq, Show)

-- IssuerAndSerialNumber ::= SEQUENCE {
--   issuer Name,
--   serialNumber CertificateSerialNumber }
instance ASN1Structure IssuerAndSerial where
    toASN1Fields IssuerAndSerial{..} = runPrintASN1State printer
        where printer = putObject issuerName
                        <> putIntVal issuerSerial
    fromASN1Fields = runParseASN1State parser
        where parser = IssuerAndSerial <$> getObject
                                       <*> getIntVal

instance ASN1Object IssuerAndSerial where
    toASN1 = toASN1Structure Sequence
    fromASN1 = fromASN1Structure Sequence

-- | X.509 Certificates.
newtype Certificate = Certificate { x509Certificate :: Data.X509.Certificate }
    deriving (Eq, Show)

instance ASN1Structure Certificate where
    toASN1Fields = toASN1 . x509Certificate
    fromASN1Fields = fmap (first Certificate) . fromASN1

instance ASN1Object Certificate where
    toASN1 = toASN1Structure Sequence
    fromASN1 = fromASN1Structure Sequence

-- | X.509 Certificate Revocation List.
newtype CRL = CRL { x509CRL :: Data.X509.CRL }
    deriving (Eq, Show)

instance ASN1Structure CRL where
    toASN1Fields = toASN1 . x509CRL
    fromASN1Fields = fmap (first CRL) . fromASN1

instance ASN1Object CRL where
    toASN1 = toASN1Structure Sequence
    fromASN1 = fromASN1Structure Sequence
