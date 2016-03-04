{-|
Module: Data.Pkcs7.Print

This module provides an ASN1 printer monoid with O(1) append and a
set of functions matching the parser in Data.Pkcs7.Parse.

Example:

@
instance ASN1Object Foo where
  toASN1 foo = runPrintASN1State printer
    where printer =    putSequence (fooList foo)
                    <> putImplicitMaybe 0 (putObject <$> fooMaybe foo)
@

Use 'fmap' or '<$>' to lift printers into lists and Maybes and
'mappend' or '<>' to concatenate output.
-}
module Data.Pkcs7.Print
    ( PrintASN1
    , runPrintASN1State
    , runPrintASN1
      -- * Primitives
    , putNext
    , putMany
    , putOID
    , putIntVal
    , putBitString
    , putOctetString
    , putTime
    , putObject
    , putObjectMaybe
    , putStructureFields
      -- * Tagging
    , putExplicit
    , putExplicitMaybe
    , putImplicit
    , putImplicitMaybe
    , putContext
    , putContextMaybe
      -- * Container
    , putMaybe
    , putSequenceOf
    , putSequenceOfMaybe
    , putSetOf
    , putSetOfMaybe
    , (<>)
    ) where

import           Data.ByteString    ( ByteString )
import           Data.Hourglass     ( DateTime, TimezoneOffset(..) )
import           Data.Maybe         ( fromMaybe )
import           Data.Monoid        ( (<>) )

import           Data.ASN1.BitArray ( BitArray )
import           Data.Pkcs7.ASN1

newtype PrintASN1 = P { runP :: ASN1S }

instance Monoid PrintASN1 where
    mempty = P id
    mappend a b = P $ runP a . runP b

-- | Run the printer producing an ASN1S, a function that prepends the
-- printed objects to an ASN1 stream.
runPrintASN1State :: PrintASN1 -> ASN1S
runPrintASN1State = runP

-- | Run the printer producing an ASN1 stream.
runPrintASN1 :: PrintASN1 -> [ASN1]
runPrintASN1 p = runP p []

-- | Put a single token into the ASN1 stream.
putNext :: ASN1 -> PrintASN1
putNext v = P $ (:) v

-- | Combine a sequence of printers into one.
putMany :: [PrintASN1] -> PrintASN1
putMany = mconcat

-- | Put an OBJECT IDENTIFIER into the ASN1 stream.
putOID :: OID -> PrintASN1
putOID oid = putNext (OID oid)

-- | Put an INTEGER into the ASN1 stream.
putIntVal :: Integer -> PrintASN1
putIntVal int = putNext (IntVal int)

-- | Put an BIT STRING into the ASN1 stream.
putBitString :: BitArray -> PrintASN1
putBitString bs = putNext (BitString bs)

-- | Put an OCTET STRING into the ASN1 stream.
putOctetString :: ByteString -> PrintASN1
putOctetString bs = putNext (OctetString bs)

-- | Put an GeneralizedTime into the ASN1 stream.
putTime :: DateTime -> PrintASN1
putTime t = putNext (ASN1Time TimeGeneralized t (Just (TimezoneOffset 0)))

-- | Put an object into the ASN1 stream using ASN1Objects toASN1.
putObject :: ASN1Object a => a -> PrintASN1
putObject o = P $ toASN1 o

-- | Maybe put an object into the ASN1 stream using ASN1Objects toASN1.
putObjectMaybe :: ASN1Object a => Maybe a -> PrintASN1
putObjectMaybe = putMaybe . fmap putObject

-- | Put an object into the ASN1 stream using ASN1Objects toASN1.
putStructureFields :: ASN1Structure a => a -> PrintASN1
putStructureFields o = P $ toASN1Fields o

-- | Put an object into the ASN1 stream wrapped in an EXPLICIT tag.
putExplicit :: ASN1Object a => Int -> a -> PrintASN1
putExplicit n o = putNext (Start (Container Context n))
    <> putObject o
    <> putNext (End (Container Context n))

-- | Maybe put an object into the ASN1 stream wrapped in an EXPLICIT tag.
putExplicitMaybe :: ASN1Object a => Int -> Maybe a -> PrintASN1
putExplicitMaybe n = putMaybe . fmap (putExplicit n)

-- | Put an object into the ASN1 stream wrapped in an IMPLICIT tag.
putImplicit :: ASN1Structure a => Int -> a -> PrintASN1
putImplicit n o = putNext (Start (Container Context n))
    <> putStructureFields o
    <> putNext (End (Container Context n))

-- | Maybe put an object into the ASN1 stream wrapped in an IMPLICIT tag.
putImplicitMaybe :: ASN1Structure a => Int -> Maybe a -> PrintASN1
putImplicitMaybe n = putMaybe . fmap (putImplicit n)

-- | Put an printer into the ASN1 stream wrapped in an CONTEXT tag.
putContext :: Int -> PrintASN1 -> PrintASN1
putContext n p = putNext (Start (Container Context n))
    <> p
    <> putNext (End (Container Context n))

-- | Maybe put an printer into the ASN1 stream wrapped in an CONTEXT tag.
putContextMaybe :: Int -> Maybe PrintASN1 -> PrintASN1
putContextMaybe n = putMaybe . fmap (putContext n)

-- | Maybe put a printer into the ASN1 stream or leave the stream
-- untouched.
putMaybe :: Maybe PrintASN1 -> PrintASN1
putMaybe = fromMaybe (P id)

-- | Put a sequence of printers into the ASN1 stream wrapped in a SEQUENCE OF.
putSequenceOf :: ASN1Object a => [a] -> PrintASN1
putSequenceOf = putObject . SequenceOf

-- | Maybe put a sequence of printers into the ASN1 stream wrapped in a SEQUENCE.
putSequenceOfMaybe :: ASN1Object a => Maybe [a] -> PrintASN1
putSequenceOfMaybe = putMaybe . fmap putSequenceOf

-- | Put a sequence of printers into the ASN1 stream wrapped in a SET OF.
putSetOf :: ASN1Object a => [a] -> PrintASN1
putSetOf = putObject . SetOf

-- | Maybe put a sequence of printers into the ASN1 stream wrapped in a SET OF.
putSetOfMaybe :: ASN1Object a => Maybe [a] -> PrintASN1
putSetOfMaybe = putMaybe . fmap putSetOf
