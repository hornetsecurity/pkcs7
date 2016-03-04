{-# LANGUAGE OverloadedStrings     #-}

{-# LANGUAGE FlexibleInstances     #-}
{-# LANGUAGE MultiParamTypeClasses #-}

{-# OPTIONS_GHC -fno-warn-orphans #-}

module Tests.Types ( testTypes ) where

import           Test.SmallCheck.Series
import           Test.Tasty
import           Test.Tasty.SmallCheck
import           Tests.Internal

import           Tests.X509             ()

import           Data.ASN1.Types        ( ASN1(..), ASN1ConstructionType(..) )
import           Data.Pkcs7.Types

instance Monad m => Serial m Data where
    series = newtypeCons Data

instance Example Data where
    example = Data "deadbeef"

instance Monad m => Serial m None where
    series = cons0 None

instance Example None where
    example = None

instance Monad m => Serial m Any where
    series = Any <$> elements [ [ Null ]
                              , [ Start Sequence, End Sequence ]
                              , [ Start Set, Null, End Set ]
                              ]

instance Example Any where
    example = Any [ Null ]

instance Monad m => Serial m Version where
    series = newtypeCons Version

instance Example Version where
    example = Version 1

instance Monad m => Serial m ContentType where
    series = ContentType <$> oidSeries

instance Example ContentType where
    example = ContentType oidExample

instance Serial m a => Serial m (ContentInfo a) where
    series = cons2 ContentInfo

instance Example a => Example (ContentInfo a) where
    example = ContentInfo example (Just example)

instance Serial m a => Serial m (AlgorithmIdentifier a) where
    series = cons2 AlgorithmIdentifier

instance Example a => Example (AlgorithmIdentifier a) where
    example = AlgorithmIdentifier example Nothing

instance (Example a, Serial m a) => Serial m (Attribute a) where
    series = decDepth $ Attribute <$> oidSeries <~> simpleListSeries

instance Example a => Example (Attribute a) where
    example = Attribute oidExample [ example ]

instance Monad m => Serial m IssuerAndSerial where
    series = cons2 IssuerAndSerial

instance Example IssuerAndSerial where
    example = IssuerAndSerial example 42

instance Monad m => Serial m Certificate where
    series = newtypeCons Certificate

instance Example Certificate where
    example = Certificate example

instance Monad m => Serial m CRL where
    series = newtypeCons CRL

instance Example CRL where
    example = CRL example

testTypes :: TestTree
testTypes =
    testGroup "Data.Pkcs7.Types"
              [ testProperty "Data" (propRoundtripASN1 :: Data -> Bool)
              , testProperty "None" (propRoundtripASN1 :: None -> Bool)
              , testProperty "Any" (propRoundtripASN1 :: Any -> Bool)
              , testProperty "Version" (propRoundtripASN1 :: Version -> Bool)
              , testProperty "ContentType" (propRoundtripASN1 :: ContentType -> Bool)
              , testProperty "ContentInfo" (propRoundtripASN1 :: ContentInfo Data -> Bool)
              , testProperty "Attribute" (propRoundtripASN1 :: Attribute Any -> Bool)
              , testProperty "IssuerAndSerial" (propRoundtripASN1 :: IssuerAndSerial -> Bool)
              , testProperty "Certificate" (propRoundtripASN1 :: Certificate -> Bool)
              , testProperty "CRL" (propRoundtripASN1 :: CRL -> Bool)
              ]



