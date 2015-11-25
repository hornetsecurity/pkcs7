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
