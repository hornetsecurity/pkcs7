{-# LANGUAGE OverloadedStrings     #-}

{-# LANGUAGE FlexibleInstances     #-}
{-# LANGUAGE MultiParamTypeClasses #-}

{-# OPTIONS_GHC -fno-warn-orphans #-}

module Tests.Internal
    ( Example(..)
    , elements
    , listSeries
    , simpleListSeries
    , simpleListSeriesExample
    , oidSeries
    , oidExample
    , propRoundtripOID
    , propRoundtripASN1
    , decodeDER
    ) where

import           Data.ASN1.BinaryEncoding (DER (..))
import           Data.ASN1.BitArray       (BitArray, toBitArray)
import           Data.ASN1.Encoding       (decodeASN1')
import           Data.ASN1.Types          (ASN1CharacterString (..),
                                           ASN1Object (..),
                                           ASN1StringEncoding (UTF8), OID,
                                           OIDNameable (..), OIDable (..))
import           Data.ByteString          (ByteString, length)
import           Data.Hourglass           (DateTime, Elapsed, timeFromElapsed)

import qualified Data.ByteString          as BS
import qualified Data.ByteString.Base64   as Base64

import           Test.SmallCheck.Series

class Example a where
    example :: a

elements :: Monad m => [a] -> Series m a
elements l = decDepth $ generate (\d -> if d >= 0 then l else [])

listSeries :: Monad m => Series m a -> Series m [a]
listSeries s = decDepth $ pure [] \/ ((:) <$> s <~> listSeries s)

simpleListSeries :: (Example a, Serial m a) => Series m [a]
simpleListSeries = simpleListSeriesExample example series

simpleListSeriesExample :: Monad m => a -> Series m a -> Series m [a]
simpleListSeriesExample e s = decDepth $ pure [] \/ ((:) <$> pure e <~> simpleListSeriesExample e s)

oidSeries :: Monad m => Series m OID
oidSeries = elements [ [], [ 1 ], [ 1, 840, 123412 ] ]

oidExample :: OID
oidExample = [ 1, 840, 123412 ]

instance Monad m => Serial m DateTime where
    series = newtypeCons (timeFromElapsed . (fromIntegral :: Int -> Elapsed))

instance Monad m => Serial m ByteString where
    series = elements [ "", "deadbeef", "lorem ipsum dolor amet sit" ]

instance Monad m => Serial m ASN1CharacterString where
    series = newtypeCons (ASN1CharacterString UTF8)

instance Monad m => Serial m BitArray where
    series = do
      bs <- series
      return $ toBitArray bs (8 * Data.ByteString.length bs)

-- Generic property to test Object -> OID -> Object roundtrip
propRoundtripOID :: (Eq a, Show a, OIDable a, OIDNameable a) => a -> Bool
propRoundtripOID o =
    case result of
      Just decoded
        | decoded == o -> True
        | otherwise    -> error ("object: " ++ show o ++ " modified during roundtrip: " ++ show decoded)
      Nothing          -> error ("object: " ++ show o ++ " failed to decode: " ++ show oid)
    where oid = getObjectID o
          result = fromObjectID oid

-- Generic property to test Object -> ASN.1 -> Object roundtrip
propRoundtripASN1 :: (Eq a, Show a, ASN1Object a) => a -> Bool
propRoundtripASN1 o =
    case result of
      Right (decoded, [])
        | decoded == o -> True
        | otherwise    -> error ("object: " ++ show o ++ " modified during roundtrip: " ++ show decoded)
      Right (_, rest)  -> error ("object: " ++ show o ++ " encoded data not consumed completely: " ++ show rest)
      Left e           -> error ("object: " ++ show o ++ " decoding failed: " ++ e)
    where encoded = toASN1 o []
          result = fromASN1 encoded

decodeDER :: ASN1Object a => BS.ByteString -> Either String a
decodeDER input = do
  binary <- Base64.decode input
  asn1 <- either (Left . show) Right $ decodeASN1' DER binary
  (o, xs) <- fromASN1 asn1
  if null xs then return o else Left "leftover ASN1 data"
