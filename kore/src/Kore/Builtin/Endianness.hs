{- |
Copyright   : (c) Runtime Verification, 2019
License     : NCSA

 -}

module Kore.Builtin.Endianness
    ( verifiers
    , littleEndianKey
    , bigEndianKey
    , unifyEquals
    , module Kore.Builtin.Endianness.Endianness
    ) where

import Control.Applicative
    ( Alternative (..)
    )
import Control.Error
    ( MaybeT
    )
import qualified Control.Monad as Monad
import qualified Control.Monad.Trans as Trans
import Data.Functor.Const
import qualified Data.HashMap.Strict as HashMap
import Data.String
    ( IsString
    )

import qualified Kore.Attribute.Symbol as Attribute.Symbol
import Kore.Builtin.Builtin
import Kore.Builtin.Endianness.Endianness
import Kore.Error
import Kore.Internal.Pattern
    ( Pattern
    )
import qualified Kore.Internal.Pattern as Pattern
import Kore.Internal.Symbol
import Kore.Internal.TermLike
import Kore.Step.Simplification.Simplify
    ( SimplifierVariable
    )
import Kore.Syntax.Application
    ( Application (..)
    )
import Kore.Unification.Unify
    ( MonadUnify
    , explainAndReturnBottom
    )
import qualified Kore.Verified as Verified

verifiers :: Verifiers
verifiers =
    mempty
        { patternVerifierHook =
            (applicationPatternVerifierHooks . HashMap.fromList)
                [ (KlabelSymbolKey littleEndianKey, littleEndianVerifier)
                , (KlabelSymbolKey bigEndianKey   , bigEndianVerifier   )
                ]
        }

littleEndianKey :: IsString str => str
littleEndianKey = "littleEndianBytes"

bigEndianKey :: IsString str => str
bigEndianKey = "bigEndianBytes"

endiannessVerifier
    :: (Symbol -> Endianness)  -- ^ Constructor
    -> ApplicationVerifier Verified.Pattern
endiannessVerifier ctor =
    ApplicationVerifier worker
  where
    worker application = do
        -- TODO (thomas.tuegel): Move the checks into the symbol verifiers.
        Monad.unless (null arguments)
            (koreFail "expected zero arguments")
        let Attribute.Symbol.SymbolKywd { isSymbolKywd } =
                Attribute.Symbol.symbolKywd $ symbolAttributes symbol
        Monad.unless isSymbolKywd
            (koreFail "expected symbol'Kywd'{}() attribute")
        return (EndiannessF . Const $ ctor symbol)
      where
        arguments = applicationChildren application
        symbol = applicationSymbolOrAlias application

littleEndianVerifier :: ApplicationVerifier Verified.Pattern
littleEndianVerifier = endiannessVerifier LittleEndian

bigEndianVerifier :: ApplicationVerifier Verified.Pattern
bigEndianVerifier = endiannessVerifier BigEndian

unifyEquals
    :: SimplifierVariable variable
    => MonadUnify unifier
    => TermLike variable
    -> TermLike variable
    -> MaybeT unifier (Pattern variable)
unifyEquals termLike1@(Endianness_ end1) termLike2@(Endianness_ end2)
  | end1 == end2 = return (Pattern.fromTermLike termLike1)
  | otherwise =
    Trans.lift $ explainAndReturnBottom
        "Cannot unify distinct constructors."
        termLike1
        termLike2
unifyEquals _ _ = empty
