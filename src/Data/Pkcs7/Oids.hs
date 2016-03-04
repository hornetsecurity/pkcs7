{-|
Module: Data.Pkcs7.Oids

OBJECT IDENTIFIER used in Data.Pkcs7.
-}
module Data.Pkcs7.Oids
    ( -- * Tools
      OIDTable
    , toOID
    , fromOID
      -- * Content Types
    , oidData
    , oidDigestedData
    , oidSignedData
    , oidEncryptedData
    , oidEnvelopedData
    , oidAuthenticatedData
      -- * Digest Algorithms
    , oidMD2
    , oidMD4
    , oidMD5
    , oidSHA1
    , oidSHA256
    , oidSHA384
    , oidSHA512
    , oidSHA224
      -- * Signature Algorithms
    , oidDSA
    , oidSHA1WithDSA
    , oidRSA
    , oidMD2WithRSA
    , oidMD4WithRSA
    , oidMD5WithRSA
    , oidSHA1WithRSA
    , oidSHA256WithRSA
    , oidSHA384WithRSA
    , oidSHA512WithRSA
    , oidSHA224WithRSA
      -- * Symmetric Encryption Algorithms
    , oidDESCBC
    , oidDESEDE3CBC
    , oidRC2
    , oidAES
    , oidAES128CBC
    , oidAES192CBC
    , oidAES256CBC
    , oidAES128CCM
    , oidAES192CCM
    , oidAES256CCM
    , oidAES128GCM
    , oidAES192GCM
    , oidAES256GCM
      -- * Key Agreement Encryption Algorithms
    , oidESDH
    , oidSSDH
      -- * Key Wrap Algorithms
    , oidDES3Wrap
    , oidRC2Wrap
      -- * Key Derivation Algorithms
    , oidPBKDF2
      -- * Message Authentication Algorithms
    , oidHMACSHA1
    ) where

import           Data.List     ( find )
import           Data.Maybe    ( fromMaybe )

import           Data.ASN1.OID ( OID )

-- a mapping between a custom value and an OBJECT IDENTIFIER
type OIDTable a = [(a, OID)]

-- lookup the OID to a given value in an OIDTable
toOID :: (Eq a, Show a) => OIDTable a -> a -> OID
toOID table v = fromMaybe (error $ "missing OID for " ++ show v) $
    lookup v table

-- lookup the value to a given OID in an OIDTable
fromOID :: Eq a => (OID -> a) -> OIDTable a -> OID -> a
fromOID def table oid = fromMaybe (def oid) $
    fst <$> find ((==) oid . snd) table

-- id-data OBJECT IDENTIFIER ::= { iso(1) member-body(2)
--   us(840) rsadsi(113549) pkcs(1) pkcs7(7) 1 }
oidData :: OID
oidData = [ 1, 2, 840, 113549, 1, 7, 1 ]

-- id-digestedData OBJECT IDENTIFIER ::= { iso(1) member-body(2)
--     us(840) rsadsi(113549) pkcs(1) pkcs7(7) 5 }
oidDigestedData :: OID
oidDigestedData = [ 1, 2, 840, 113549, 1, 7, 5 ]

-- id-signedData OBJECT IDENTIFIER ::= { iso(1) member-body(2)
--    us(840) rsadsi(113549) pkcs(1) pkcs7(7) 2 }
oidSignedData :: OID
oidSignedData = [ 1, 2, 840, 113549, 1, 7, 2 ]

-- id-encryptedData OBJECT IDENTIFIER ::= { iso(1) member-body(2)
--     us(840) rsadsi(113549) pkcs(1) pkcs7(7) 6 }
oidEncryptedData :: OID
oidEncryptedData = [ 1, 2, 840, 113549, 1, 7, 6 ]

-- id-envelopedData OBJECT IDENTIFIER ::= { iso(1) member-body(2)
--     us(840) rsadsi(113549) pkcs(1) pkcs7(7) 3 }
oidEnvelopedData :: OID
oidEnvelopedData = [ 1, 2, 840, 113549, 1, 7, 3 ]

-- id-ct-authData OBJECT IDENTIFIER ::= { iso(1) member-body(2)
--     us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16)
--     ct(1) 2 }
oidAuthenticatedData :: OID
oidAuthenticatedData = [ 1, 2, 840, 113549, 1, 9, 16, 1, 2 ]

-- md2 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840)
--     rsadsi(113549) digestAlgorithm(2) 2 }
oidMD2 :: OID
oidMD2 = [ 1, 2, 840, 113549, 2, 2 ]

-- md4 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840)
--     rsadsi(113549) digestAlgorithm(2) 4 }
oidMD4 :: OID
oidMD4 = [ 1, 2, 840, 113549, 2, 4 ]

-- md5 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840)
--     rsadsi(113549) digestAlgorithm(2) 5 }
oidMD5 :: OID
oidMD5 = [ 1, 2, 840, 113549, 2, 5 ]

-- sha-1 OBJECT IDENTIFIER ::= { iso(1) identified-organization(3)
--     oiw(14) secsig(3) algorithm(2) 26 }
oidSHA1 :: OID
oidSHA1 = [ 1, 3, 14, 3, 2, 26 ]

-- id-dsa OBJECT IDENTIFIER ::= { iso(1) member-body(2)
--     us(840) x9-57 (10040) x9cm(4) 1 }
oidDSA :: OID
oidDSA = [ 1, 2, 840, 10040, 4, 1 ]

-- id-dsa-with-sha1 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
--     us(840) x9-57 (10040) x9cm(4) 3 }
oidSHA1WithDSA :: OID
oidSHA1WithDSA = [ 1, 2, 840, 10040, 4, 3 ]

-- rsaEncryption OBJECT IDENTIFIER ::= { iso(1) member-body(2)
--     us(840) rsadsi(113549) pkcs(1) pkcs-1(1) 1 }
oidRSA :: OID
oidRSA = [ 1, 2, 840, 113549, 1, 1, 1 ]

-- md2WithRSAEncryption OBJECT IDENTIFIER ::= { iso(1)
--     member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1) 2 }
oidMD2WithRSA :: OID
oidMD2WithRSA = [ 1, 2, 840, 113549, 1, 1, 2 ]

-- md4WithRSAEncryption OBJECT IDENTIFIER ::= { iso(1)
--     member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1) 3 }
oidMD4WithRSA :: OID
oidMD4WithRSA = [ 1, 2, 840, 113549, 1, 1, 3 ]

-- md5WithRSAEncryption OBJECT IDENTIFIER ::= { iso(1)
--     member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1) 4 }
oidMD5WithRSA :: OID
oidMD5WithRSA = [ 1, 2, 840, 113549, 1, 1, 4 ]

-- sha1WithRSAEncryption OBJECT IDENTIFIER ::= { iso(1)
--     member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1) 5 }
oidSHA1WithRSA :: OID
oidSHA1WithRSA = [ 1, 2, 840, 113549, 1, 1, 5 ]

-- sha256WithRSAEncryption OBJECT IDENTIFIER ::= { iso(1)
--     member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1) 11 }
oidSHA256WithRSA :: OID
oidSHA256WithRSA = [ 1, 2, 840, 113549, 1, 1, 11 ]

-- sha384WithRSAEncryption OBJECT IDENTIFIER ::= { iso(1)
--     member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1) 12 }
oidSHA384WithRSA :: OID
oidSHA384WithRSA = [ 1, 2, 840, 113549, 1, 1, 12 ]

-- sha512WithRSAEncryption OBJECT IDENTIFIER ::= { iso(1)
--     member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1) 13 }
oidSHA512WithRSA :: OID
oidSHA512WithRSA = [ 1, 2, 840, 113549, 1, 1, 13 ]

-- sha224WithRSAEncryption OBJECT IDENTIFIER ::= { iso(1)
--     member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1) 14 }
oidSHA224WithRSA :: OID
oidSHA224WithRSA = [ 1, 2, 840, 113549, 1, 1, 14 ]

-- sha-256 OBJECT IDENTIFIER ::= { joint-iso-itu-t(2) country(16)
--     us(840) organization(1) gov(101) csor(3) nistAlgorithm(4)
--     hashAlgs(2) sha256(1) }
oidSHA256 :: OID
oidSHA256 = [ 2, 16, 840, 1, 101, 3, 4, 2, 1 ]

-- sha-384 OBJECT IDENTIFIER ::= { joint-iso-itu-t(2) country(16)
--     us(840) organization(1) gov(101) csor(3) nistAlgorithm(4)
--     hashAlgs(2) sha384(2) }
oidSHA384 :: OID
oidSHA384 = [ 2, 16, 840, 1, 101, 3, 4, 2, 2 ]

-- sha-512 OBJECT IDENTIFIER ::= { joint-iso-itu-t(2) country(16)
--     us(840) organization(1) gov(101) csor(3) nistAlgorithm(4)
--     hashAlgs(2) sha512(3) }
oidSHA512 :: OID
oidSHA512 = [ 2, 16, 840, 1, 101, 3, 4, 2, 3 ]

-- sha-224 OBJECT IDENTIFIER ::= { joint-iso-itu-t(2) country(16)
--     us(840) organization(1) gov(101) csor(3) nistAlgorithm(4)
--     hashAlgs(2) sha224(4) }
oidSHA224 :: OID
oidSHA224 = [ 2, 16, 840, 1, 101, 3, 4, 2, 4 ]

oidDESCBC :: OID
oidDESCBC = [ 1, 3, 14, 3, 2, 7 ]

-- des-ede3-cbc OBJECT IDENTIFIER ::= { iso(1) member-body(2)
--     us(840) rsadsi(113549) encryptionAlgorithm(3) 7 }
oidDESEDE3CBC :: OID
oidDESEDE3CBC = [ 1, 2, 840, 113549, 3, 7 ]

-- rc2-cbc OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840)
--     rsadsi(113549) encryptionAlgorithm(3) 2 }
oidRC2 :: OID
oidRC2 = [ 1, 2, 840, 113549, 3, 2 ]

-- aes OBJECT IDENTIFIER ::= { joint-iso-itu-t(2) country(16) us(840)
--     organization(1) gov(101) csor(3) nistAlgorithm(4) 1 }
oidAES :: OID
oidAES = [ 2, 16, 840, 1, 101, 3, 4, 1 ]

-- id-aes128-CBC OBJECT IDENTIFIER ::= { aes 2 }
oidAES128CBC :: OID
oidAES128CBC = oidAES ++ [ 2 ]

-- id-aes192-CBC OBJECT IDENTIFIER ::= { aes 22 }
oidAES192CBC :: OID
oidAES192CBC = oidAES ++ [ 22 ]

-- id-aes256-CBC OBJECT IDENTIFIER ::= { aes 42 }
oidAES256CBC :: OID
oidAES256CBC = oidAES ++ [ 42 ]

-- id-aes128-CCM OBJECT IDENTIFIER ::= { aes 7 }
oidAES128CCM :: OID
oidAES128CCM = oidAES ++ [ 7 ]

-- id-aes192-CCM OBJECT IDENTIFIER ::= { aes 27 }
oidAES192CCM :: OID
oidAES192CCM = oidAES ++ [ 27 ]

-- id-aes256-CCM OBJECT IDENTIFIER ::= { aes 47 }
oidAES256CCM :: OID
oidAES256CCM = oidAES ++ [ 47 ]

-- id-aes128-GCM OBJECT IDENTIFIER ::= { aes 6 }
oidAES128GCM :: OID
oidAES128GCM = oidAES ++ [ 6 ]

-- id-aes192-GCM OBJECT IDENTIFIER ::= { aes 26 }
oidAES192GCM :: OID
oidAES192GCM = oidAES ++ [ 26 ]

-- id-aes256-GCM OBJECT IDENTIFIER ::= { aes 46 }
oidAES256GCM :: OID
oidAES256GCM = oidAES ++ [ 46 ]

-- id-alg-ESDH OBJECT IDENTIFIER ::= { iso(1) member-body(2)
--     us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16)
--     alg(3) 5 }
oidESDH :: OID
oidESDH = [ 1, 2, 840, 113549, 1, 9, 16, 3, 5 ]

-- id-alg-SSDH OBJECT IDENTIFIER ::= { iso(1) member-body(2)
--     us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16)
--     alg(3) 10 }
oidSSDH :: OID
oidSSDH = [ 1, 2, 840, 113549, 1, 9, 16, 3, 10 ]

-- id-alg-CMS3DESwrap OBJECT IDENTIFIER ::= { iso(1) member-body(2)
--     us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) alg(3) 6 }
oidDES3Wrap :: OID
oidDES3Wrap = [ 1, 2, 840, 113549, 1, 9, 16, 3, 6 ]

-- id-alg-CMSRC2wrap OBJECT IDENTIFIER ::= { iso(1) member-body(2)
--     us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) alg(3) 7 }
oidRC2Wrap :: OID
oidRC2Wrap = [ 1, 2, 840, 113549, 1, 9, 16, 3, 7 ]

-- id-PBKDF2 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840)
--     rsadsi(113549) pkcs(1) pkcs-5(5) 12 }
oidPBKDF2 :: OID
oidPBKDF2 = [ 1, 2, 840, 113549, 1, 5, 12 ]

-- hMAC-SHA1 OBJECT IDENTIFIER ::= { iso(1)
--    identified-organization(3) dod(6) internet(1) security(5)
--    mechanisms(5) 8 1 2 }
oidHMACSHA1 :: OID
oidHMACSHA1 = [ 1, 3, 6, 1, 5, 5, 8, 1, 2 ]
