{-# LANGUAGE OverloadedStrings     #-}

{-# LANGUAGE FlexibleInstances     #-}
{-# LANGUAGE MultiParamTypeClasses #-}

{-# OPTIONS_GHC -fno-warn-orphans #-}

module Tests.AuthenticatedData ( testAuthenticatedData ) where

import           Test.SmallCheck.Series
import           Test.Tasty
import           Test.Tasty.SmallCheck
import           Tests.Internal

import           Tests.EnvelopedData          ()
import           Tests.SignedData             ()
import           Tests.Types                  ()

import           Data.Pkcs7.AuthenticatedData
import           Data.Pkcs7.Types

instance Monad m => Serial m MessageAuthenticationCodeAlgorithm where
    series = cons0 MessageAuthenticationCodeHMACSHA1
        \/ decDepth (MessageAuthenticationCodeUnknown <$> oidSeries)

instance Example MessageAuthenticationCodeAlgorithm where
    example = MessageAuthenticationCodeHMACSHA1

instance Monad m => Serial m MessageAuthenticationCode where
    series = newtypeCons MessageAuthenticationCode

instance Example MessageAuthenticationCode where
    example = MessageAuthenticationCode "deadbeef"

instance Serial m a => Serial m (AuthenticatedData a) where
    series =
        AuthenticatedData <$> pure example
                          <~> elements [ Nothing, Just example ]
                          <~> elements [ [], [ example ] ]
                          <~> pure example
                          <~> elements [ Nothing, Just example ]
                          <~> series
                          <~> elements [ Nothing, Just [], Just [ example ] ]
                          <~> pure example
                          <~> elements [ Nothing, Just [], Just [ example ] ]

instance Monad m => Serial m AuthEnvelopedData where
    series = decDepth $
        AuthEnvelopedData <$> pure example
                          <~> series
                          <~> (cons0 [] \/ cons1 (: []))
                          <~> pure example
                          <~> elements [ Nothing, Just [], Just [ example ] ]
                          <~> pure example
                          <~> elements [ Nothing, Just [], Just [ example ] ]

testAuthenticatedData :: TestTree
testAuthenticatedData =
    testGroup "Data.Pkcs7.AuthenticatedData"
              [ testProperty "MessageAuthenticationCodeAlgorithm" (propRoundtripOID :: MessageAuthenticationCodeAlgorithm -> Bool)
              , testProperty "MessageAuthenticationCode" (propRoundtripASN1 :: MessageAuthenticationCode -> Bool)
              , testProperty "AuthenticatedData" (propRoundtripASN1 :: AuthenticatedData Data -> Bool)
              , testProperty "AuthEnvelopedData" (propRoundtripASN1 :: AuthEnvelopedData -> Bool)
              ]
