{- |
Module      : Kore.Builtin.Krypto
Description : Built-in cryptographic functions.
Copyright   : (c) Runtime Verification, 2018
License     : NCSA
Maintainer  : vladimir.ciobanu@runtimeverification.com
Stability   : experimental
Portability : portable

This module is intended to be imported qualified, to avoid collision with other
builtin modules.

@
    import qualified Kore.Builtin.Krypto as Krypto
@
 -}

module Kore.Builtin.Krypto
    ( symbolVerifiers
    , builtinFunctions
    , keccakKey
    , keccakKeyT
    ) where

import           Crypto.Hash
                 ( Digest, Keccak_512, hash )
import           Data.ByteArray
                 ( ScrubbedBytes )
import           Data.ByteString.Char8
                 ( pack )
import qualified Data.HashMap.Strict as HashMap
import           Data.Map
                 ( Map )
import qualified Data.Map as Map
import           Data.String
                 ( fromString )
import           Data.Text
                 ( Text )

import           Kore.AST.MetaOrObject
                 ( Object )
import qualified Kore.Builtin.Builtin as Builtin
import qualified Kore.Builtin.String as String
import           Kore.IndexedModule.MetadataTools
                 ( MetadataTools )
import           Kore.Sort
                 ( Sort )
import           Kore.Step.Function.Data
                 ( AttemptedFunction )
import           Kore.Step.Pattern
import           Kore.Step.Simplification.Data
                 ( Simplifier, StepPatternSimplifier )
import           Kore.Step.StepperAttributes
                 ( StepperAttributes )

import Debug.Trace

keccakKey :: String
keccakKey = "KRYPTO.keccak256"
keccakKeyT :: Text
keccakKeyT = "KRYPTO.keccak256"

{- | Verify that hooked symbol declarations are well-formed.

  See also: 'Builtin.verifySymbol'

-}
symbolVerifiers :: Builtin.SymbolVerifiers
symbolVerifiers =
    HashMap.fromList
    [ ( keccakKeyT
      , Builtin.verifySymbol String.assertSort [String.assertSort]
      )
    ]

{- | Implement builtin function evaluation.
 -}
builtinFunctions :: Map Text Builtin.Function
builtinFunctions =
    Map.fromList
        [ (keccakKeyT, evalKeccak)
        ]

evalKeccak :: Builtin.Function
evalKeccak =
    Builtin.functionEvaluator evalKeccak0
  where
    evalKeccak0
        :: (Ord (variable Object), Show (variable Object))
        => MetadataTools Object StepperAttributes
        -> StepPatternSimplifier Object variable
        -> Sort Object
        -> [StepPattern Object variable]
        -> Simplifier (AttemptedFunction Object variable)
    evalKeccak0 _ _ resultSort arguments =
        Builtin.getAttemptedFunction $ do
            traceM "arguments: \n"
            traceShowM arguments
            let
                arg =
                    case arguments of
                      [input] -> input
                      _ -> Builtin.wrongArity keccakKey
            traceM "arg: \n"
            traceShowM arg
            str <- String.expectBuiltinString keccakKey arg
            traceM "str: \n"
            traceM $ "'" <> str <> "'|'" <> show str <> "'"
            let
                bytes = fromString str :: ScrubbedBytes
                -- digest = hash bytes :: Digest Keccak_512
                digest = hash . pack $ str :: Digest Keccak_512
                result = "0x" <> show digest
            traceM $ "----\n'" <> str <> "'\n" <> result <> "\n--------"
            Builtin.appliedFunction $ String.asExpandedPattern resultSort result
