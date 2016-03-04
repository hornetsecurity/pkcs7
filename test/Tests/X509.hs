{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE RecordWildCards       #-}

{-# LANGUAGE FlexibleInstances     #-}
{-# LANGUAGE MultiParamTypeClasses #-}

{-# OPTIONS_GHC -fno-warn-orphans #-}

module Tests.X509 ( testX509 ) where

import           Data.ASN1.Types        ( ASN1StringEncoding(UTF8) )
import           Data.Hourglass         ( timeFromElapsed )

import           Test.SmallCheck.Series
import           Test.Tasty
import           Test.Tasty.SmallCheck
import           Tests.Internal

import qualified Crypto.PubKey.DSA      as DSA
import qualified Crypto.PubKey.RSA      as RSA
import           Data.X509

instance Monad m => Serial m DistinguishedName where
    series = decDepth $ DistinguishedName <$> listSeries items
      where
        items = oidSeries >< elements [ "", "lorem" ]

instance Example DistinguishedName where
    example = DistinguishedName [ ([ 1 ], ASN1CharacterString UTF8 "lorem") ]

instance Monad m => Serial m RSA.PublicKey where
    series = decDepth $ do
        bytes <- cons0 64 \/ cons0 128 \/ cons0 256
        e <- cons0 0x3 \/ cons0 0x10001
        n <- cons0 (2 ^ (8 * bytes) - 1)
        return RSA.PublicKey { RSA.public_size = bytes
                             , RSA.public_n = n
                             , RSA.public_e = e
                             }

instance Example RSA.PublicKey where
    example = RSA.PublicKey { RSA.public_size = bytes
                            , RSA.public_n = n
                            , RSA.public_e = e
                            }
      where
        bytes = 128
        e = 0x10001
        n = 2 ^ (8 * bytes) - 1

instance Monad m => Serial m DSA.Params where
    series = cons3 DSA.Params

instance Monad m => Serial m DSA.PublicKey where
    series = cons2 DSA.PublicKey

instance Monad m => Serial m PubKey where
    series = cons1 PubKeyRSA \/ cons1 PubKeyDSA

instance Example PubKey where
    example = PubKeyRSA example

instance Monad m => Serial m SignatureALG where
    -- unfortunately as the encoding of this is a single OID as opposed to two OID,
    -- the testing need to limit itself to Signature ALG that has been defined in the OI
    -- arbitrary = SignatureALG <$> arbitrary <*> arbitrary
    series = elements [ SignatureALG HashSHA1 PubKeyALG_RSA
                      , SignatureALG HashMD5 PubKeyALG_RSA
                      , SignatureALG HashMD2 PubKeyALG_RSA
                      , SignatureALG HashSHA256 PubKeyALG_RSA
                      , SignatureALG HashSHA384 PubKeyALG_RSA
                      , SignatureALG HashSHA512 PubKeyALG_RSA
                      , SignatureALG HashSHA224 PubKeyALG_RSA
                      , SignatureALG HashSHA1 PubKeyALG_DSA
                      , SignatureALG HashSHA224 PubKeyALG_EC
                      , SignatureALG HashSHA256 PubKeyALG_EC
                      , SignatureALG HashSHA384 PubKeyALG_EC
                      , SignatureALG HashSHA512 PubKeyALG_EC
                      ]

instance Monad m => Serial m Certificate where
    series = decDepth $
        Certificate <$> pure 1
                    <~> pure 123456                -- certSerial
                    <~> series                     -- certSignatureAlg
                    <~> pure example               -- certIssuerDN
                    <~> series                     -- certValidity
                    <~> pure example               -- certSubjectDN
                    <~> pure example               -- certPubKey
                    <~> cons0 (Extensions Nothing) -- certExtension

instance Example Certificate where
    example = Certificate { .. }
      where
        certVersion = 1
        certSerial = 123456
        certSignatureAlg = SignatureALG HashSHA256 PubKeyALG_RSA
        certIssuerDN = example
        certValidity = (timeFromElapsed 0, timeFromElapsed (365 * 86400))
        certSubjectDN = example
        certPubKey = PubKeyRSA example
        certExtensions = Extensions Nothing

instance Monad m => Serial m CRL where
    series = decDepth $
        CRL <$> pure 1
            <~> series                    -- crlSignatureAlg = SignatureALG HashSHA1 PubKeyALG_RSA
            <~> pure example              -- crlIssuer = DistinguishedName []
            <~> series                    -- crlThisUpdate = timeFromElapsed 123
            <~> series                    -- crlNextUpdate = Nothing
            <~> pure []                   -- crlRevokedCertificates = []
            <~> pure (Extensions Nothing) -- crlExtensions = Extensions Nothing

instance Example CRL where
    example = CRL { .. }
      where
        crlVersion = 1
        crlSignatureAlg = SignatureALG HashSHA1 PubKeyALG_RSA
        crlIssuer = DistinguishedName []
        crlThisUpdate = timeFromElapsed 0
        crlNextUpdate = Just (timeFromElapsed 86400)
        crlRevokedCertificates = []
        crlExtensions = Extensions Nothing

testX509 :: TestTree
testX509 =
    testGroup "Data.X509"
              [ testProperty "Data.X509.DistinguishedName" (propRoundtripASN1 :: DistinguishedName -> Bool)
              , testProperty "Data.X509.PubKey" (propRoundtripASN1 :: PubKey -> Bool)
              , testProperty "Data.X509.SignatureALG" (propRoundtripASN1 :: SignatureALG -> Bool)
              , testProperty "Data.X509.DistinguishedName" (propRoundtripASN1 :: DistinguishedName -> Bool)
              , testProperty "Data.X509.Certificate" (propRoundtripASN1 :: Certificate -> Bool)
              , testProperty "Data.X509.CRL" (propRoundtripASN1 :: CRL -> Bool)
              ]
