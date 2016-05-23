{-# LANGUAGE RecordWildCards #-}

{-|
Module: Data.Pkcs7.EnvelopedData

Data types for encrypted data in PKCS#7.
-}
module Data.Pkcs7.EnvelopedData
    ( KeyEncryptionAlgorithm(..)
    , KeyEncryptionAlgorithmIdentifier
    , KeyAgreementAlgorithm(..)
    , KeyAgreementAlgorithmIdentifier
    , KeyWrapAlgorithm(..)
    , KeyWrapAlgorithmIdentifier
    , KeyDerivationAlgorithm(..)
    , KeyDerivationAlgorithmIdentifier
    , ContentEncryptionAlgorithm(..)
    , ContentEncryptionAlgorithmIdentifier
    , Originator(..)
    , KeyTransportRecipientIdentifier(..)
    , KeyTransport(..)
    , OriginatorPublicKey(..)
    , OriginatorIdentifierOrKey(..)
    , UserKeyingMaterial(..)
    , KeyAgreementRecipientIdentifier(..)
    , RecipientEncryptedKey(..)
    , KeyAgreement(..)
    , KEKIdentifier(..)
    , RecipientKeyIdentifier(..)
    , OtherKeyAttribute(..)
    , KEK(..)
    , EncryptedKey(..)
    , Password(..)
    , Recipient(..)
    , EncryptedContent(..)
    , EnvelopedData(..)
    ) where

import           Data.ByteString          ( ByteString )
import           Data.Hourglass           ( DateTime )

import           Data.ASN1.BitArray       ( BitArray )
import           Data.Pkcs7.ASN1
import           Data.Pkcs7.Parse
import           Data.Pkcs7.Print

import           Data.Pkcs7.Oids
import           Data.Pkcs7.Types

import           Data.Pkcs7.EncryptedData ( ContentEncryptionAlgorithm(..)
                                          , ContentEncryptionAlgorithmIdentifier
                                          , EncryptedContent(..) )
import           Data.Pkcs7.SignedData    ( CertificateChoice(..)
                                          , RevocationChoice(..)
                                          , SignatureAlgorithmIdentifier
                                          , SubjectKeyIdentifier(..) )

-- | Asymmetric algorithms to encrypt symmetric encryption keys.
data KeyEncryptionAlgorithm = KeyEncryptionRSA
                            | KeyEncryptionUnknown OID
    deriving (Eq, Show)

keaTable :: OIDTable KeyEncryptionAlgorithm
keaTable = [ (KeyEncryptionRSA, oidRSA) ]

instance OIDable KeyEncryptionAlgorithm where
    getObjectID (KeyEncryptionUnknown oid) = oid
    getObjectID v = toOID keaTable v

instance OIDNameable KeyEncryptionAlgorithm where
    fromObjectID = Just . fromOID KeyEncryptionUnknown keaTable

type KeyEncryptionAlgorithmIdentifier = AlgorithmIdentifier KeyEncryptionAlgorithm

-- | Algorithms for key agreement.
data KeyAgreementAlgorithm = KeyAgreementESDH
                           | KeyAgreementSSDH
                           | KeyAgreementUnknown OID
    deriving (Eq, Show)

kaaTable :: OIDTable KeyAgreementAlgorithm
kaaTable = [ (KeyAgreementESDH, oidESDH), (KeyAgreementSSDH, oidSSDH) ]

instance OIDable KeyAgreementAlgorithm where
    getObjectID (KeyAgreementUnknown oid) = oid
    getObjectID v = toOID kaaTable v

instance OIDNameable KeyAgreementAlgorithm where
    fromObjectID = Just . fromOID KeyAgreementUnknown kaaTable

type KeyAgreementAlgorithmIdentifier = AlgorithmIdentifier KeyAgreementAlgorithm

-- | Algorithms for key wrap.
data KeyWrapAlgorithm = KeyWrapDES3
                      | KeyWrapRC2
                      | KeyWrapUnknown OID
    deriving (Eq, Show)

kwaTable :: OIDTable KeyWrapAlgorithm
kwaTable = [ (KeyWrapDES3, oidDES3Wrap), (KeyWrapRC2, oidRC2Wrap) ]

instance OIDable KeyWrapAlgorithm where
    getObjectID (KeyWrapUnknown oid) = oid
    getObjectID v = toOID kwaTable v

instance OIDNameable KeyWrapAlgorithm where
    fromObjectID = Just . fromOID KeyWrapUnknown kwaTable

type KeyWrapAlgorithmIdentifier = AlgorithmIdentifier KeyWrapAlgorithm

-- | Algorithms to derive keys from passwords.
data KeyDerivationAlgorithm = KeyDerivationPBKDF2
                            | KeyDerivationUnknown OID
    deriving (Eq, Show)

kdaTable :: OIDTable KeyDerivationAlgorithm
kdaTable = [ (KeyDerivationPBKDF2, oidPBKDF2) ]

instance OIDable KeyDerivationAlgorithm where
    getObjectID (KeyDerivationUnknown oid) = oid
    getObjectID v = toOID kdaTable v

instance OIDNameable KeyDerivationAlgorithm where
    fromObjectID = Just . fromOID KeyDerivationUnknown kdaTable

type KeyDerivationAlgorithmIdentifier = AlgorithmIdentifier KeyDerivationAlgorithm

-- | Identifying information for a message originator.
data Originator = Originator { originatorCerts :: Maybe [CertificateChoice]
                             , originatorCrls  :: Maybe [RevocationChoice]
                             }
    deriving (Eq, Show)

-- OriginatorInfo ::= SEQUENCE {
--   certs [0] IMPLICIT CertificateSet OPTIONAL,
--   crls [1] IMPLICIT RevocationInfoChoices OPTIONAL }
--
-- CertificateSet ::= SET OF CertificateChoices
--
-- RevocationInfoChoices ::= SET OF RevocationInfoChoice
instance ASN1Structure Originator where
    toASN1Fields Originator{..} = runPrintASN1State printer
      where
        printer = putImplicitMaybe 0 (SetOf <$> originatorCerts)
            <> putImplicitMaybe 1 (SetOf <$> originatorCrls)
    fromASN1Fields = runParseASN1State parser
      where
        parser = Originator <$> (fmap unSetOf <$> getImplicitMaybe 0)
                            <*> (fmap unSetOf <$> getImplicitMaybe 1)

instance ASN1Object Originator where
    toASN1 = toASN1Structure Sequence
    fromASN1 = fromASN1Structure Sequence

-- | Identifying material for key transport recipients.
data KeyTransportRecipientIdentifier =
      KeyTransportRecipientIssuerAndSerial IssuerAndSerial
    | KeyTransportRecipientSubjectKeyIdentifier SubjectKeyIdentifier
    deriving (Eq, Show)

--  RecipientIdentifier ::= CHOICE {
--    issuerAndSerialNumber IssuerAndSerialNumber,
--    subjectKeyIdentifier [0] SubjectKeyIdentifier }
instance ASN1Object KeyTransportRecipientIdentifier where
    toASN1 o = runPrintASN1State printer
      where
        printer = case o of
            KeyTransportRecipientIssuerAndSerial o' -> putObject o'
            KeyTransportRecipientSubjectKeyIdentifier o' -> putExplicit 0 o'
    fromASN1 = runParseASN1State parser
      where
        parser =
            (fmap KeyTransportRecipientSubjectKeyIdentifier <$> getExplicitMaybe 0)
            `orChoiceDefault`
            (KeyTransportRecipientIssuerAndSerial <$> getObject)

-- | Key transport information.
data KeyTransport =
    KeyTransport { keyTransportVersion             :: Version
                 , keyTransportRecipient           :: KeyTransportRecipientIdentifier
                 , keyTransportEncryptionAlgorithm :: KeyEncryptionAlgorithmIdentifier
                 , keyTransportEncryptedKey        :: EncryptedKey
                 }
    deriving (Eq, Show)

-- KeyTransRecipientInfo ::= SEQUENCE {
--    version CMSVersion,  -- always set to 0 or 2
--    rid RecipientIdentifier,
--    keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
--    encryptedKey EncryptedKey }
instance ASN1Structure KeyTransport where
    toASN1Fields KeyTransport{..} = runPrintASN1State printer
      where
        printer = putObject keyTransportVersion
            <> putObject keyTransportRecipient
            <> putObject keyTransportEncryptionAlgorithm
            <> putObject keyTransportEncryptedKey
    fromASN1Fields = runParseASN1State parser
      where
        parser =
            KeyTransport <$> getObject <*> getObject <*> getObject <*> getObject

instance ASN1Object KeyTransport where
    toASN1 = toASN1Structure Sequence
    fromASN1 = fromASN1Structure Sequence

data OriginatorPublicKey =
    OriginatorPublicKey { originatorPublicKeyAlgorithm :: SignatureAlgorithmIdentifier
                        , originatorPublicKey          :: BitArray
                        }
    deriving (Eq, Show)

-- OriginatorPublicKey ::= SEQUENCE {
--   algorithm AlgorithmIdentifier,
--   publicKey BIT STRING }
instance ASN1Structure OriginatorPublicKey where
    toASN1Fields OriginatorPublicKey{..} = runPrintASN1State printer
      where
        printer = putObject originatorPublicKeyAlgorithm
            <> putBitString originatorPublicKey
    fromASN1Fields = runParseASN1State parser
      where
        parser = OriginatorPublicKey <$> getObject <*> getBitString

instance ASN1Object OriginatorPublicKey where
    toASN1 = toASN1Structure Sequence
    fromASN1 = fromASN1Structure Sequence

data OriginatorIdentifierOrKey =
      OriginatorIssuerAndSerial IssuerAndSerial
    | OriginatorSubjectKeyIdentifier SubjectKeyIdentifier
    | OriginatorKey OriginatorPublicKey
    deriving (Eq, Show)

-- OriginatorIdentifierOrKey ::= CHOICE {
--   issuerAndSerialNumber IssuerAndSerialNumber,
--   subjectKeyIdentifier [0] SubjectKeyIdentifier,
--   originatorKey [1] OriginatorPublicKey }
instance ASN1Object OriginatorIdentifierOrKey where
    toASN1 o = runPrintASN1State printer
      where
        printer = case o of
            OriginatorIssuerAndSerial o' -> putObject o'
            OriginatorSubjectKeyIdentifier o' -> putExplicit 0 o'
            OriginatorKey o' -> putExplicit 1 o'
    fromASN1 = runParseASN1State parser
      where
        parser = (fmap OriginatorKey <$> getExplicitMaybe 1)
                 `orChoice`
                 (fmap OriginatorSubjectKeyIdentifier <$> getExplicitMaybe 0)
                 `orChoiceDefault`
                 (OriginatorIssuerAndSerial <$> getObject)

newtype UserKeyingMaterial = UserKeyingMaterial ByteString
    deriving (Eq, Show)

-- UserKeyingMaterial ::= OCTET STRING
instance ASN1Object UserKeyingMaterial where
    toASN1 (UserKeyingMaterial bs) = runPrintASN1State printer
      where
        printer = putOctetString bs
    fromASN1 = runParseASN1State parser
      where
        parser = UserKeyingMaterial <$> getOctetString

data KeyAgreementRecipientIdentifier =
      KeyAgreementRecipientIdentifierIssuerAndSerial IssuerAndSerial
    | KeyAgreementRecipientIdentifierKeyIdentifier RecipientKeyIdentifier
    deriving (Eq, Show)

-- KeyAgreeRecipientIdentifier ::= CHOICE {
--   issuerAndSerialNumber IssuerAndSerialNumber,
--   rKeyId [0] IMPLICIT RecipientKeyIdentifier }
instance ASN1Object KeyAgreementRecipientIdentifier where
    toASN1 o = runPrintASN1State printer
      where
        printer = case o of
            KeyAgreementRecipientIdentifierIssuerAndSerial o' -> putObject o'
            KeyAgreementRecipientIdentifierKeyIdentifier o' -> putImplicit 0 o'
    fromASN1 = runParseASN1State parser
      where
        parser =
            (fmap KeyAgreementRecipientIdentifierKeyIdentifier <$> getImplicitMaybe 0)
            `orChoiceDefault`
            (KeyAgreementRecipientIdentifierIssuerAndSerial <$> getObject)

data RecipientEncryptedKey =
    RecipientEncryptedKey { recipientEncryptedKeyIdentifier :: KeyAgreementRecipientIdentifier
                          , recipientEncryptedKey           :: EncryptedKey
                          }
    deriving (Eq, Show)

-- RecipientEncryptedKey ::= SEQUENCE {
--   rid KeyAgreeRecipientIdentifier,
--   encryptedKey EncryptedKey }
instance ASN1Structure RecipientEncryptedKey where
    toASN1Fields RecipientEncryptedKey{..} = runPrintASN1State printer
      where
        printer = putObject recipientEncryptedKeyIdentifier
            <> putObject recipientEncryptedKey
    fromASN1Fields = runParseASN1State parser
      where
        parser = RecipientEncryptedKey <$> getObject <*> getObject

instance ASN1Object RecipientEncryptedKey where
    toASN1 = toASN1Structure Sequence
    fromASN1 = fromASN1Structure Sequence

data KeyAgreement =
    KeyAgreement { keyAgreementVersion                :: Version
                 , keyAgreementOriginator             :: OriginatorIdentifierOrKey
                 , keyAgreementUserKeyingMaterial     :: Maybe UserKeyingMaterial
                 , keyAgreementEncryptionAlgorithm    :: KeyAgreementAlgorithmIdentifier
                 , keyAgreementRecipientEncryptedKeys :: [RecipientEncryptedKey]
                 }
    deriving (Eq, Show)

-- KeyAgreeRecipientInfo ::= SEQUENCE {
--   version CMSVersion,  -- always set to 3
--   originator [0] EXPLICIT OriginatorIdentifierOrKey,
--   ukm [1] EXPLICIT UserKeyingMaterial OPTIONAL,
--   keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
--   recipientEncryptedKeys RecipientEncryptedKeys }
--
-- RecipientEncryptedKeys ::= SEQUENCE OF RecipientEncryptedKey
instance ASN1Structure KeyAgreement where
    toASN1Fields KeyAgreement{..} = runPrintASN1State printer
      where
        printer = putObject keyAgreementVersion
            <> putExplicit 0 keyAgreementOriginator
            <> putExplicitMaybe 1 keyAgreementUserKeyingMaterial
            <> putObject keyAgreementEncryptionAlgorithm
            <> putSequenceOf keyAgreementRecipientEncryptedKeys
    fromASN1Fields = runParseASN1State parser
      where
        parser = KeyAgreement <$> getObject
                              <*> getExplicit 0
                              <*> getExplicitMaybe 1
                              <*> getObject
                              <*> getSequenceOf

instance ASN1Object KeyAgreement where
    toASN1 = toASN1Structure Sequence
    fromASN1 = fromASN1Structure Sequence

data RecipientKeyIdentifier =
    RecipientKeyIdentifier { recipientKeyIdentifier :: SubjectKeyIdentifier
                           , recipientKeyTime       :: Maybe DateTime
                           , recipientKeyAttribute  :: Maybe (OtherKeyAttribute Any)
                           }
    deriving (Eq, Show)

-- RecipientKeyIdentifier ::= SEQUENCE {
--    subjectKeyIdentifier SubjectKeyIdentifier,
--    date GeneralizedTime OPTIONAL,
--    other OtherKeyAttribute OPTIONAL }
instance ASN1Structure RecipientKeyIdentifier where
    toASN1Fields RecipientKeyIdentifier{..} = runPrintASN1State printer
      where
        printer = putObject recipientKeyIdentifier
            <> putMaybe (putTime <$> recipientKeyTime)
            <> putMaybe (putObject <$> recipientKeyAttribute)
    fromASN1Fields = runParseASN1State parser
      where
        parser = RecipientKeyIdentifier <$> getObject
                                        <*> getNextMaybe toDateTime
                                        <*> getObjectMaybe
        toDateTime (ASN1Time _ t _) = Just t
        toDateTime _ = Nothing

instance ASN1Object RecipientKeyIdentifier where
    toASN1 = toASN1Structure Sequence
    fromASN1 = fromASN1Structure Sequence

data OtherKeyAttribute a = OtherKeyAttribute { keyAttributeIdentifier :: OID
                                             , keyAttributeValue      :: Maybe a
                                             }
    deriving (Eq, Show)

-- OtherKeyAttribute ::= SEQUENCE {
--   keyAttrId OBJECT IDENTIFIER,
--   keyAttr ANY DEFINED BY keyAttrId OPTIONAL }
instance ASN1Object a => ASN1Structure (OtherKeyAttribute a) where
    toASN1Fields OtherKeyAttribute{..} = runPrintASN1State printer
      where
        printer = putOID keyAttributeIdentifier
            <> putObjectMaybe keyAttributeValue
    fromASN1Fields = runParseASN1State parser
      where
        parser = OtherKeyAttribute <$> getOID <*> getObjectMaybe

instance ASN1Object a => ASN1Object (OtherKeyAttribute a) where
    toASN1 = toASN1Structure Sequence
    fromASN1 = fromASN1Structure Sequence

data KEKIdentifier =
    KEKIdentifier { kekIdentifierValue :: ByteString
                  , kekIdentifierTime  :: Maybe DateTime
                  , kekIdentifierOther :: Maybe (OtherKeyAttribute Any)
                  }
    deriving (Eq, Show)

-- KEKIdentifier ::= SEQUENCE {
--   keyIdentifier OCTET STRING,
--   date GeneralizedTime OPTIONAL,
--   other OtherKeyAttribute OPTIONAL }
instance ASN1Structure KEKIdentifier where
    toASN1Fields KEKIdentifier{..} = runPrintASN1State printer
      where
        printer = putOctetString kekIdentifierValue
            <> putMaybe (putTime <$> kekIdentifierTime)
            <> putMaybe (putObject <$> kekIdentifierOther)
    fromASN1Fields = runParseASN1State parser
      where
        parser = KEKIdentifier <$> getOctetString
                               <*> getNextMaybe toDateTime
                               <*> getObjectMaybe
        toDateTime (ASN1Time _ t _) = Just t
        toDateTime _ = Nothing

instance ASN1Object KEKIdentifier where
    toASN1 = toASN1Structure Sequence
    fromASN1 = fromASN1Structure Sequence

data KEK = KEK { kekVersion             :: Version
               , kekIdentifier          :: KEKIdentifier
               , kekEncryptionAlgorithm :: KeyWrapAlgorithmIdentifier
               , kekEncryptedKey        :: EncryptedKey
               }
    deriving (Eq, Show)

-- KEKRecipientInfo ::= SEQUENCE {
--   version CMSVersion,  -- always set to 4
--   kekid KEKIdentifier,
--   keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
--   encryptedKey EncryptedKey }
instance ASN1Structure KEK where
    toASN1Fields KEK{..} = runPrintASN1State printer
      where
        printer = putObject kekVersion
            <> putObject kekIdentifier
            <> putObject kekEncryptionAlgorithm
            <> putObject kekEncryptedKey
    fromASN1Fields = runParseASN1State parser
      where
        parser = KEK <$> getObject <*> getObject <*> getObject <*> getObject

instance ASN1Object KEK where
    toASN1 = toASN1Structure Sequence
    fromASN1 = fromASN1Structure Sequence

newtype EncryptedKey = EncryptedKey ByteString
    deriving (Eq, Show)

-- EncryptedKey ::= OCTET STRING
instance ASN1Object EncryptedKey where
    toASN1 (EncryptedKey bs) = runPrintASN1State printer
      where
        printer = putOctetString bs
    fromASN1 = runParseASN1State parser
      where
        parser = EncryptedKey <$> getOctetString

data Password =
    Password { passwordVersion                :: Version
             , passwordKeyDerivationAlgorithm :: Maybe KeyDerivationAlgorithmIdentifier
             , passwordEncryptionAlgorithm    :: KeyEncryptionAlgorithmIdentifier
             , passwordEncryptedKey           :: EncryptedKey
             }
    deriving (Eq, Show)

-- PasswordRecipientInfo ::= SEQUENCE {
--   version CMSVersion,   -- Always set to 0
--   keyDerivationAlgorithm [0] KeyDerivationAlgorithmIdentifier OPTIONAL,
--   keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
--   encryptedKey EncryptedKey }
instance ASN1Structure Password where
    toASN1Fields Password{..} = runPrintASN1State printer
      where
        printer = putObject passwordVersion
            <> putImplicitMaybe 0 passwordKeyDerivationAlgorithm
            <> putObject passwordEncryptionAlgorithm
            <> putObject passwordEncryptedKey
    fromASN1Fields = runParseASN1State parser
      where
        parser = Password <$> getObject
                          <*> getImplicitMaybe 0
                          <*> getObject
                          <*> getObject

instance ASN1Object Password where
    toASN1 = toASN1Structure Sequence
    fromASN1 = fromASN1Structure Sequence

data Recipient = RecipientKeyTransport KeyTransport
               | RecipientKeyAgreement KeyAgreement
               | RecipientKEK KEK
               | RecipientPassword Password
               | RecipientOther OID Any
    deriving (Eq, Show)

-- RecipientInfo ::= CHOICE {
--    ktri KeyTransRecipientInfo,
--    kari [1] KeyAgreeRecipientInfo,
--    kekri [2] KEKRecipientInfo,
--    pwri [3] PasswordRecipientinfo,
--    ori [4] OtherRecipientInfo }
--
-- OtherRecipientInfo ::= SEQUENCE {
--   oriType OBJECT IDENTIFIER,
--   oriValue ANY DEFINED BY oriType }
instance ASN1Object Recipient where
    toASN1 o = runPrintASN1State printer
      where
        printer = case o of
            RecipientKeyTransport o' -> putObject o'
            RecipientKeyAgreement o' -> putExplicit 1 o'
            RecipientKEK o' -> putExplicit 2 o'
            RecipientPassword o' -> putExplicit 3 o'
            RecipientOther oid d -> putContext 4 (putOID oid <> putObject d)
    fromASN1 = runParseASN1State parser
      where
        parser = onContextMaybe 4 (RecipientOther <$> getOID <*> getObject)
                 `orChoice`
                 (fmap RecipientPassword <$> getExplicitMaybe 3)
                 `orChoice`
                 (fmap RecipientKEK <$> getExplicitMaybe 2)
                 `orChoice`
                 (fmap RecipientKeyAgreement <$> getExplicitMaybe 1)
                 `orChoiceDefault`
                 (RecipientKeyTransport <$> getObject)

data EnvelopedData =
    EnvelopedData { envelopedVersion               :: Version
                  , envelopedOriginator            :: Maybe Originator
                  , envelopedRecipients            :: [Recipient]
                  , envelopedEncryptedContent      :: EncryptedContent
                  , envelopedUnprotectedAttributes :: Maybe [Attribute Data]
                  }
    deriving (Eq, Show)

-- id-envelopedData OBJECT IDENTIFIER ::= { iso(1) member-body(2)
--   us(840) rsadsi(113549) pkcs(1) pkcs7(7) 3 }
instance OIDable EnvelopedData where
    getObjectID _ = [ 1, 2, 840, 113549, 1, 7, 3 ]

-- EnvelopedData ::= SEQUENCE {
--   version CMSVersion,
--   originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
--   recipientInfos RecipientInfos,
--   encryptedContentInfo EncryptedContentInfo,
--   unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }
--
-- RecipientInfos ::= SET SIZE (1..MAX) OF RecipientInfo
--
-- UnprotectedAttributes ::= SET SIZE (1..MAX) OF Attribute
instance ASN1Structure EnvelopedData where
    toASN1Fields EnvelopedData{..} = runPrintASN1State printer
      where
        printer = putObject envelopedVersion
            <> putImplicitMaybe 0 envelopedOriginator
            <> putSetOf envelopedRecipients
            <> putObject envelopedEncryptedContent
            <> putImplicitMaybe 1 (SetOf <$> envelopedUnprotectedAttributes)
    fromASN1Fields = runParseASN1State parser
      where
        parser = EnvelopedData <$> getObject
                               <*> getImplicitMaybe 0
                               <*> getSetOf
                               <*> getObject
                               <*> (fmap unSetOf <$> getImplicitMaybe 1)

instance ASN1Object EnvelopedData where
    toASN1 = toASN1Structure Sequence
    fromASN1 = fromASN1Structure Sequence
