module Main (main) where

import           Test.Tasty

import           Tests.DigestedData
import           Tests.SignedData
import           Tests.Types
import           Tests.X509

main :: IO ()
main = defaultMain $ testGroup "Tests" [ testX509
                                       , testTypes
                                       , testDigestedData
                                       , testSignedData
                                       ]
