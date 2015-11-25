{-# LANGUAGE OverloadedStrings     #-}

{-# LANGUAGE FlexibleInstances     #-}
{-# LANGUAGE MultiParamTypeClasses #-}

{-# OPTIONS_GHC -fno-warn-orphans #-}

module Tests.DigestedData ( testDigestedData ) where

import           Test.SmallCheck.Series
import           Test.Tasty
import           Test.Tasty.SmallCheck
import           Tests.Internal

import           Tests.Types             ()

import           Data.Pkcs7.DigestedData
import           Data.Pkcs7.Types

instance Monad m => Serial m DigestAlgorithm where
    series = cons0 DigestMD2
             \/ cons0 DigestMD4
             \/ cons0 DigestMD5
             \/ cons0 DigestSHA1
             \/ cons0 DigestSHA256
             \/ cons0 DigestSHA384
             \/ cons0 DigestSHA512
             \/ cons0 DigestSHA224
             \/ decDepth (DigestUnknown <$> oidSeries)

instance Example DigestAlgorithm where
    example = DigestSHA1

instance Monad m => Serial m Digest where
    series = newtypeCons Digest

instance Example Digest where
    example = Digest "deadbeef"

instance Serial m a => Serial m (DigestedData a) where
    series = decDepth $ DigestedData <$> pure example
                                     <~> series
                                     <~> series
                                     <~> series

testDigestedData :: TestTree
testDigestedData = testGroup "Data.Pkcs7.DigestedData"
                   [ testProperty "DigestAlgorithm" (propRoundtripOID :: DigestAlgorithm -> Bool)
                   , testProperty "Digest" (propRoundtripASN1 :: Digest -> Bool)
                   , testProperty "DigestedData" (propRoundtripASN1 :: DigestedData Data -> Bool)
                   ]



