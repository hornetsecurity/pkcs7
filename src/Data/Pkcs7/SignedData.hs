{-# LANGUAGE RecordWildCards #-}

{-|
Module: Data.Pkcs7.SignedData

Data types for cryptographic signatures in PKCS#7.
-}
module Data.Pkcs7.SignedData
    ( DigestAlgorithm(..)
    , DigestAlgorithmIdentifier
    , SignatureAlgorithm(..)
    , SignatureAlgorithmIdentifier
    , Signature(..)
    , ExtendedCertificate(..)
    , Signed(..)
    , CertificateChoice(..)
    , RevocationChoice(..)
    , SubjectKeyIdentifier(..)
    , SignerIdentifier(..)
    , Signer(..)
    , SignedData(..)
    ) where

import           Data.ASN1.BitArray      ( BitArray )
import           Data.ByteArray          ( constEq )
import           Data.ByteString         ( ByteString )

import           Data.Pkcs7.ASN1
import           Data.Pkcs7.Parse
import           Data.Pkcs7.Print

import           Data.Pkcs7.Oids
import           Data.Pkcs7.Types

import           Data.Pkcs7.DigestedData ( DigestAlgorithm(..)
                                         , DigestAlgorithmIdentifier )

-- | Asymmetric algorithms to encrypt message digests.
data SignatureAlgorithm =
      SignatureDSA
    | SignatureSHA1WithDSA
    | SignatureRSA
    | SignatureMD2WithRSA
    | SignatureMD4WithRSA
    | SignatureMD5WithRSA
    | SignatureSHA1WithRSA
    | SignatureSHA256WithRSA
    | SignatureSHA384WithRSA
    | SignatureSHA512WithRSA
    | SignatureSHA224WithRSA
    | SignatureUnknown OID
    deriving (Eq, Show)

saTable :: OIDTable SignatureAlgorithm
saTable = [ (SignatureDSA, oidDSA)
          , (SignatureSHA1WithDSA, oidSHA1WithDSA)
          , (SignatureRSA, oidRSA)
          , (SignatureMD2WithRSA, oidMD2WithRSA)
          , (SignatureMD4WithRSA, oidMD4WithRSA)
          , (SignatureMD5WithRSA, oidMD5WithRSA)
          , (SignatureSHA1WithRSA, oidSHA1WithRSA)
          , (SignatureSHA256WithRSA, oidSHA256WithRSA)
          , (SignatureSHA384WithRSA, oidSHA384WithRSA)
          , (SignatureSHA512WithRSA, oidSHA512WithRSA)
          , (SignatureSHA224WithRSA, oidSHA224WithRSA)
          ]

instance OIDable SignatureAlgorithm where
    getObjectID (SignatureUnknown oid) = oid
    getObjectID v = toOID saTable v

instance OIDNameable SignatureAlgorithm where
    fromObjectID = Just . fromOID SignatureUnknown saTable

type SignatureAlgorithmIdentifier = AlgorithmIdentifier SignatureAlgorithm

-- | A cryptographic signature obtained using a given digest algorithm
-- and encryption scheme.
newtype Signature = Signature ByteString
    deriving (Show)

instance Eq Signature where
    (Signature left) == (Signature right) = left `constEq` right

instance ASN1Object Signature where
    toASN1 (Signature bs) = runPrintASN1State printer
      where
        printer = putOctetString bs
    fromASN1 = runParseASN1State parser
      where
        parser = Signature <$> getOctetString

-- | Extended certificates.
data ExtendedCertificate =
      ExtendedCertificate { extendedCertificateVersion                   :: Version
                          , extendedCertificateCertificate               :: Certificate
                          , extendedCertificateUnauthenticatedAttributes :: [Attribute Any]
                          }
    deriving (Eq, Show)

-- ExtendedCertificateInfo ::= SEQUENCE {
--   version CMSVersion,
--   certificate Certificate,
--   attributes UnauthAttributes }
--
-- UnauthAttributes ::= SET SIZE (1..MAX) OF Attribute
instance ASN1Structure ExtendedCertificate where
    toASN1Fields ExtendedCertificate{..} = runPrintASN1State printer
      where
        printer = putObject extendedCertificateVersion
            <> putObject extendedCertificateCertificate
            <> putSetOf extendedCertificateUnauthenticatedAttributes
    fromASN1Fields = runParseASN1State parser
      where
        parser = ExtendedCertificate <$> getObject <*> getObject <*> getSetOf

instance ASN1Object ExtendedCertificate where
    toASN1 = toASN1Structure Sequence
    fromASN1 = fromASN1Structure Sequence

-- | ASN.1 object with an accompanying cryptographics signature.
data Signed a = Signed { signedObject             :: a
                       , signedSignatureAlgorithm :: SignatureAlgorithmIdentifier
                       , signedSignature          :: BitArray
                       }
    deriving (Eq, Show)

instance ASN1Object a => ASN1Structure (Signed a) where
    toASN1Fields Signed{..} = runPrintASN1State printer
      where
        printer = putObject signedObject
            <> putObject signedSignatureAlgorithm
            <> putBitString signedSignature
    fromASN1Fields = runParseASN1State parser
      where
        parser = Signed <$> getObject <*> getObject <*> getBitString

instance ASN1Object a => ASN1Object (Signed a) where
    toASN1 = toASN1Structure Sequence
    fromASN1 = fromASN1Structure Sequence

-- | Different options for including certificates within SignedData.
data CertificateChoice =
      CertificateCertificate (Signed Certificate)
    | CertificateExtended (Signed ExtendedCertificate)
    | CertificateAttributeCertificateV1 (Signed Any)
    | CertificateAttributeCertificateV2 (Signed Any)
    | CertificateOther OID Any
    deriving (Eq, Show)

-- CertificateChoices ::= CHOICE {
--   certificate Certificate,
--   extendedCertificate [0] IMPLICIT ExtendedCertificate, -- Obsolete
--   v1AttrCert [1] IMPLICIT AttributeCertificateV1,       -- Obsolete
--   v2AttrCert [2] IMPLICIT AttributeCertificateV2,
--   other [3] IMPLICIT OtherCertificateFormat }
--
-- AttributeCertificateV2 ::= AttributeCertificate
--
-- ExtendedCertificate ::= SEQUENCE {
--   extendedCertificateInfo ExtendedCertificateInfo,
--   signatureAlgorithm SignatureAlgorithmIdentifier,
--   signature Signature }
--
-- OtherCertificateFormat ::= SEQUENCE {
--   otherCertFormat OBJECT IDENTIFIER,
--   otherCert ANY DEFINED BY otherCertFormat }
instance ASN1Object CertificateChoice where
    toASN1 o = runPrintASN1State printer
      where
        printer = case o of
            CertificateCertificate o' -> putObject o'
            CertificateExtended o' -> putImplicit 0 o'
            CertificateAttributeCertificateV1 o' -> putImplicit 1 o'
            CertificateAttributeCertificateV2 o' -> putImplicit 2 o'
            CertificateOther oid o' -> putContext 3 (putOID oid <> putObject o')
    fromASN1 = runParseASN1State parser
      where
        parser = onContextMaybe 3 (CertificateOther <$> getOID <*> getObject)
                 `orChoice`
                 (fmap CertificateAttributeCertificateV2 <$> getImplicitMaybe 2)
                 `orChoice`
                 (fmap CertificateAttributeCertificateV1 <$> getImplicitMaybe 1)
                 `orChoice`
                 (fmap CertificateExtended <$> getImplicitMaybe 0)
                 `orChoiceDefault`
                 (CertificateCertificate <$> getObject)

-- | Certificate revocation data.
data RevocationChoice = RevocationCRL CRL
                      | RevocationOther OID Any
    deriving (Eq, Show)

instance ASN1Object RevocationChoice where
    toASN1 o = runPrintASN1State printer
      where
        printer = case o of
            RevocationCRL o' -> putObject o'
            RevocationOther oid o' -> putContext 0 (putOID oid <> putObject o')
    fromASN1 = runParseASN1State parser
      where
        parser = onContextMaybe 0 (RevocationOther <$> getOID <*> getObject)
                 `orChoiceDefault`
                 (RevocationCRL <$> getObject)

-- | Identifying a signer via a subject-key-identifier.
newtype SubjectKeyIdentifier = SubjectKeyIdentifier ByteString
    deriving (Eq, Show)

instance ASN1Object SubjectKeyIdentifier where
    toASN1 (SubjectKeyIdentifier bs) = runPrintASN1State printer
      where
        printer = putOctetString bs
    fromASN1 = runParseASN1State parser
      where
        parser = SubjectKeyIdentifier <$> getOctetString

-- | Identifying information for a signer.
data SignerIdentifier = SignerIssuerAndSerial IssuerAndSerial
                      | SignerSubjectKeyIdentifier SubjectKeyIdentifier
    deriving (Eq, Show)

-- SignerIdentifier ::= CHOICE {
--   issuerAndSerialNumber IssuerAndSerialNumber,
--   subjectKeyIdentifier [0] SubjectKeyIdentifier }
instance ASN1Object SignerIdentifier where
    toASN1 o = runPrintASN1State printer
      where
        printer = case o of
            SignerIssuerAndSerial o' -> putObject o'
            SignerSubjectKeyIdentifier o' -> putExplicit 0 o'
    fromASN1 = runParseASN1State parser
      where
        parser = (fmap SignerSubjectKeyIdentifier <$> getExplicitMaybe 0)
                 `orChoiceDefault`
                 (SignerIssuerAndSerial <$> getObject)

-- | Information about a single cryptographic signature.
data Signer = Signer { signerVersion                   :: Version
                     , signerIdentifier                :: SignerIdentifier
                     , signerDigestAlgorithm           :: DigestAlgorithmIdentifier
                     , signerAuthenticatedAttributes   :: Maybe [Attribute Any]
                     , signerSignatureAlgorithm        :: SignatureAlgorithmIdentifier
                     , signerSignature                 :: Signature
                     , signerUnauthenticatedAttributes :: Maybe [Attribute Any]
                     }
    deriving (Eq, Show)

-- SignerInfo ::= SEQUENCE {
--    version CMSVersion,
--    sid SignerIdentifier,
--    digestAlgorithm DigestAlgorithmIdentifier,
--    signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
--    signatureAlgorithm SignatureAlgorithmIdentifier,
--    signature SignatureValue,
--    unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }
--
-- SignedAttributes ::= SET SIZE (1..MAX) OF Attribute
--
-- UnsignedAttributes ::= SET SIZE (1..MAX) OF Attribute
--
-- SignatureValue ::= OCTET STRING
instance ASN1Structure Signer where
    toASN1Fields Signer{..} = runPrintASN1State printer
      where
        printer = putObject signerVersion
            <> putObject signerIdentifier
            <> putObject signerDigestAlgorithm
            <> putImplicitMaybe 0 (SetOf <$> signerAuthenticatedAttributes)
            <> putObject signerSignatureAlgorithm
            <> putObject signerSignature
            <> putImplicitMaybe 1 (SetOf <$> signerUnauthenticatedAttributes)
    fromASN1Fields = runParseASN1State parser
      where
        parser = Signer <$> getObject
                        <*> getObject
                        <*> getObject
                        <*> (fmap unSetOf <$> getImplicitMaybe 0)
                        <*> getObject
                        <*> getObject
                        <*> (fmap unSetOf <$> getImplicitMaybe 1)

instance ASN1Object Signer where
    toASN1 = toASN1Structure Sequence
    fromASN1 = fromASN1Structure Sequence

-- | Representation of arbitrary data, verifiable by zero or more
-- cryptographic signatures.
data SignedData a = SignedData { signedVersion          :: Version
                               , signedDigestAlgorithms :: [DigestAlgorithmIdentifier]
                               , signedContentInfo      :: ContentInfo a
                               , signedCertificates     :: Maybe [CertificateChoice]
                               , signedCrls             :: Maybe [RevocationChoice]
                               , signedSigners          :: [Signer]
                               }
    deriving (Eq, Show)

-- id-signedData OBJECT IDENTIFIER ::= { iso(1) member-body(2)
--   us(840) rsadsi(113549) pkcs(1) pkcs7(7) 2 }
instance OIDable (SignedData a) where
    getObjectID _ = [ 1, 2, 840, 113549, 1, 7, 2 ]

-- SignedData ::= SEQUENCE {
--   version CMSVersion,
--   digestAlgorithms DigestAlgorithmIdentifiers,
--   encapContentInfo EncapsulatedContentInfo,
--   certificates [0] IMPLICIT CertificateSet OPTIONAL,
--   crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
--   signerInfos SignerInfos }
--
-- DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier
--
-- CertificateSet ::= SET OF CertificateChoices
--
-- RevocationInfoChoices ::= SET OF RevocationInfoChoice
--
-- SignerInfos ::= SET OF SignerInfo
instance ASN1Object a => ASN1Structure (SignedData a) where
    toASN1Fields SignedData{..} = runPrintASN1State printer
      where
        printer = putObject signedVersion
            <> putSetOf signedDigestAlgorithms
            <> putObject signedContentInfo
            <> putImplicitMaybe 0 (SetOf <$> signedCertificates)
            <> putImplicitMaybe 1 (SetOf <$> signedCrls)
            <> putSetOf signedSigners
    fromASN1Fields = runParseASN1State parser
      where
        parser = SignedData <$> getObject
                            <*> getSetOf
                            <*> getObject
                            <*> (fmap unSetOf <$> getImplicitMaybe 0)
                            <*> (fmap unSetOf <$> getImplicitMaybe 1)
                            <*> getSetOf

instance ASN1Object a => ASN1Object (SignedData a) where
    toASN1 = toASN1Structure Sequence
    fromASN1 = fromASN1Structure Sequence
