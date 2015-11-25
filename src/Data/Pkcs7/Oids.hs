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
      -- * Digest Algorithms
    , oidMD2
    , oidMD4
    , oidMD5
    , oidSHA1
    , oidSHA256
    , oidSHA384
    , oidSHA512
    , oidSHA224
    ) where

import           Data.List     (find)
import           Data.Maybe    (fromMaybe)

import           Data.ASN1.OID (OID)

-- a mapping between a custom value and an OBJECT IDENTIFIER
type OIDTable a = [ (a, OID) ]

-- lookup the OID to a given value in an OIDTable
toOID :: (Eq a, Show a) => OIDTable a -> a -> OID
toOID table v = fromMaybe (error $ "missing OID for " ++ show v) $ lookup v table

-- lookup the value to a given OID in an OIDTable
fromOID :: Eq a => (OID -> a) -> OIDTable a -> OID -> a
fromOID def table oid = fromMaybe (def oid) $ fst <$> find ((==) oid . snd) table

-- id-data OBJECT IDENTIFIER ::= { iso(1) member-body(2)
--   us(840) rsadsi(113549) pkcs(1) pkcs7(7) 1 }
oidData :: OID
oidData = [ 1, 2, 840, 113549, 1, 7, 1 ]

-- id-digestedData OBJECT IDENTIFIER ::= { iso(1) member-body(2)
--     us(840) rsadsi(113549) pkcs(1) pkcs7(7) 5 }
oidDigestedData :: OID
oidDigestedData = [ 1, 2, 840, 113549, 1, 7, 5 ]

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
