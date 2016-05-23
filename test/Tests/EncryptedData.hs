{-# LANGUAGE FlexibleInstances     #-}
{-# LANGUAGE MultiParamTypeClasses #-}

{-# OPTIONS_GHC -fno-warn-orphans #-}

module Tests.EncryptedData ( testEncryptedData ) where

import           Test.SmallCheck.Series
import           Test.Tasty
import           Test.Tasty.SmallCheck
import           Tests.Internal

import           Tests.Types              ()

import           Data.Pkcs7.EncryptedData

instance Monad m => Serial m ContentEncryptionAlgorithm where
    series = cons0 ContentEncryptionDESCBC
        \/ cons0 ContentEncryptionDESEDE3CBC
        \/ cons0 ContentEncryptionRC2
        \/ cons0 ContentEncryptionAES128CBC
        \/ cons0 ContentEncryptionAES192CBC
        \/ cons0 ContentEncryptionAES256CBC
        \/ cons0 ContentEncryptionAES128CCM
        \/ cons0 ContentEncryptionAES192CCM
        \/ cons0 ContentEncryptionAES256CCM
        \/ cons0 ContentEncryptionAES128GCM
        \/ cons0 ContentEncryptionAES192GCM
        \/ cons0 ContentEncryptionAES256GCM
        \/ decDepth (ContentEncryptionUnknown <$> oidSeries)

instance Example ContentEncryptionAlgorithm where
    example = ContentEncryptionAES128CBC

instance Monad m => Serial m EncryptedContent where
    series = decDepth $ EncryptedContent <$> series <~> pure example <~> series

instance Example EncryptedContent where
    example = EncryptedContent example example (Just example)

instance Monad m => Serial m EncryptedData where
    series = decDepth $ EncryptedData <$> pure example <~> series <~> series

testEncryptedData :: TestTree
testEncryptedData =
    testGroup "Data.Pkcs7.EncryptedData"
              [ testProperty "ContentEncryptionAlgorithm" (propRoundtripOID :: ContentEncryptionAlgorithm -> Bool)
              , testProperty "EncryptedContent" (propRoundtripASN1 :: EncryptedContent -> Bool)
              , testProperty "EncryptedData" (propRoundtripASN1 :: EncryptedData -> Bool)
              ]
