{-|
Module: Data.Pkcs7.ASN1

Extensions to Data.ASN1.Types module from the asn1-types package.
This module is used internally for ASN1 parsing.
-}
module Data.Pkcs7.ASN1
    ( module Data.ASN1.Types
    , ASN1Structure(..)
    , SequenceOf(..)
    , SetOf(..)
    , toASN1Structure
    , fromASN1Structure
    ) where

import           Data.ASN1.Types

import           Data.ASN1.Parse (getMany, getNextContainer, getObject,
                                  runParseASN1State, throwParseError)

-- | Companion class to ASN1Object.  ASN1Object should encode/decode
-- the default representation for the outermost container
-- (e.g. SEQUENCE), whereas ASN1Structure should only encode/decode
-- the structure's fields.  The distinction is necessary to enable
-- IMPLICIT tagged fields.
class ASN1Object a => ASN1Structure a where
    toASN1Fields :: a -> ASN1S
    fromASN1Fields :: [ASN1] -> Either String (a, [ASN1])

newtype SequenceOf a = SequenceOf { unSequenceOf :: [a] }
newtype SetOf a = SetOf { unSetOf :: [a] }

instance ASN1Object a => ASN1Structure (SequenceOf a) where
    toASN1Fields = foldr ((.) . toASN1) id . unSequenceOf
    fromASN1Fields = runParseASN1State parser
        where parser = SequenceOf <$> getMany getObject

instance ASN1Object a => ASN1Object (SequenceOf a) where
    toASN1 = toASN1Structure Sequence
    fromASN1 = fromASN1Structure Sequence

instance ASN1Object a => ASN1Structure (SetOf a) where
    toASN1Fields = foldr ((.) . toASN1) id . unSetOf
    fromASN1Fields = runParseASN1State parser
        where parser = SetOf <$> getMany getObject

instance ASN1Object a => ASN1Object (SetOf a) where
    toASN1 = toASN1Structure Set
    fromASN1 = fromASN1Structure Set

toASN1Structure :: ASN1Structure a => ASN1ConstructionType -> a -> [ASN1] -> [ASN1]
toASN1Structure t o l = Start t : toASN1Fields o (End t : l)

fromASN1Structure :: ASN1Structure a => ASN1ConstructionType -> [ASN1] -> Either String (a, [ASN1])
fromASN1Structure t = runParseASN1State parser
    where parser = do
            l <- getNextContainer t
            case fromASN1Fields l of
              Left e        -> throwParseError e
              Right (a, []) -> return a
              Right (_, l') -> throwParseError $ "leftover ASN1: " ++ show l'
