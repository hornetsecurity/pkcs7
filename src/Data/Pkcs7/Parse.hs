{-|
Module: Data.Pkcs7.Parse

Extensions to Data.ASN1.Parse module from the asn1-parse package.
This module is used internally for ASN1 parsing.
-}
module Data.Pkcs7.Parse
    ( module Data.ASN1.Parse
      -- * Primitives
    , getOID
    , getIntVal
    , getBitString
    , getOctetString
    , getTime
    , getObjectMaybe
      -- * Tagging
    , getExplicit
    , getExplicitMaybe
    , getImplicit
    , getImplicitMaybe
    , onContext
    , onContextMaybe
      -- * Container
    , getSequenceOf
    , getSequenceOfMaybe
    , getSetOf
    , getSetOfMaybe
    , orChoice
    , orChoiceDefault
    ) where

import           Control.Applicative ( (<|>), liftA2 )

import           Data.ByteString     ( ByteString )
import           Data.Hourglass      ( DateTime )

import           Data.ASN1.BitArray  ( BitArray )
import           Data.ASN1.Parse
import           Data.Pkcs7.ASN1

newtype Fields a = Fields { unFields :: a }
    deriving (Eq, Show)

instance ASN1Structure a => ASN1Object (Fields a) where
    toASN1 = toASN1Fields . unFields
    fromASN1 xs = fromASN1Fields xs >>= (\(o, xs') -> return (Fields o, xs'))

-- | Extract an OBJECT IDENTIFIER from the ASN1 stream.
getOID :: ParseASN1 OID
getOID = getNext >>= toOID
  where
    toOID (OID oid) = return oid
    toOID _ = throwParseError "OBJECT IDENTIFIER expected"

-- | Extract an INTEGER from the ASN1 stream.
getIntVal :: ParseASN1 Integer
getIntVal = getNext >>= toIntVal
  where
    toIntVal (IntVal int) = return int
    toIntVal _ = throwParseError "INTEGER expected"

-- | Extract an BIT STRING from the ASN1 stream.
getBitString :: ParseASN1 BitArray
getBitString = getNext >>= toBitString
  where
    toBitString (BitString int) = return int
    toBitString _ = throwParseError "BIT STRING expected"

-- | Extract an OCTET STRING from the ASN1 stream.
getOctetString :: ParseASN1 ByteString
getOctetString = getNext >>= toOctetString
  where
    toOctetString (OctetString int) = return int
    toOctetString _ = throwParseError "OCTET STRING expected"

-- | Extract an GeneralizedTime from the ASN1 stream.
getTime :: ParseASN1 DateTime
getTime = getNext >>= toTime
  where
    toTime (ASN1Time _ t _) = return t
    toTime _ = throwParseError "GeneralizedTime expected"

-- | Extract an object from the ASN1 stream or nothing if the stream is empty.
getObjectMaybe :: ASN1Object a => ParseASN1 (Maybe a)
getObjectMaybe = hasNext >>=
    (\b -> if b then Just <$> getObject else return Nothing)

-- | Extract the fields of an ASN1Structure from the ASN1 stream.
getStructureFields :: ASN1Structure a => ParseASN1 a
getStructureFields = unFields <$> getObject

-- | Extract an EXPLICIT tagged object from the ASN1 stream.
getExplicit :: ASN1Object a => Int -> ParseASN1 a
getExplicit n = onNextContainer (Container Context n) getObject

-- | Extract an EXPLICIT tagged object from the ASN1 stream or nothing
-- if the next token is not the matching tag.
getExplicitMaybe :: ASN1Object a => Int -> ParseASN1 (Maybe a)
getExplicitMaybe n = onNextContainerMaybe (Container Context n) getObject

-- | Extract an IMPLICIT tagged structured SEQUENCE object from the
-- ASN1 stream.
getImplicit :: ASN1Structure a => Int -> ParseASN1 a
getImplicit n = onNextContainer (Container Context n) getStructureFields

-- | Extract an IMPLICIT tagged structured SEQUENCE object from the
-- ASN1 stream or nothing if the next token is not the matching tag.
getImplicitMaybe :: ASN1Structure a => Int -> ParseASN1 (Maybe a)
getImplicitMaybe n = onNextContainerMaybe (Container Context n)
                                          getStructureFields

-- | Extract a CONTEXT tagged sequence of ASN1 objects from the
-- ASN1 stream.
onContext :: Int -> ParseASN1 a -> ParseASN1 a
onContext n = onNextContainer (Container Context n)

-- | Extract a CONTEXT tagged sequence of ASN1 objects from the
-- ASN1 stream or nothing if the next token is not the matching tag.
onContextMaybe :: Int -> ParseASN1 a -> ParseASN1 (Maybe a)
onContextMaybe n = onNextContainerMaybe (Container Context n)

-- | Extract a SEQUENCE OF of objects from the ASN1 stream.
getSequenceOf :: ASN1Object a => ParseASN1 [a]
getSequenceOf = unSequenceOf <$> getObject

-- | Extract a SEQUENCE OF objects from the ASN1 stream or nothing if
-- the next token is not a SEQUENCE start.
getSequenceOfMaybe :: ASN1Object a => ParseASN1 (Maybe [a])
getSequenceOfMaybe = onNextContainerMaybe Sequence (getMany getObject)

-- | Extract a SET OF objects from the ASN1 stream.
getSetOf :: ASN1Object a => ParseASN1 [a]
getSetOf = unSetOf <$> getObject

-- | Extract a SET OF objects from the ASN1 stream or nothing if the
-- next token is not a SET start.
getSetOfMaybe :: ASN1Object a => ParseASN1 (Maybe [a])
getSetOfMaybe = onNextContainerMaybe Set (getMany getObject)

-- | ...
orChoice :: ParseASN1 (Maybe a) -> ParseASN1 (Maybe a) -> ParseASN1 (Maybe a)
orChoice = liftA2 (<|>)

-- | ...
orChoiceDefault :: ParseASN1 (Maybe a) -> ParseASN1 a -> ParseASN1 a
orChoiceDefault l r = l >>= maybe r return
