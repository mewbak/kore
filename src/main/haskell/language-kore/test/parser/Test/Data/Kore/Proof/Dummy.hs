{-|
Module      : Test.Data.Kore.Proof.Dummy
Description : Dummy instances of stuff for testing.
Copyright   : (c) Runtime Verification, 2018
License     : UIUC/NCSA
Maintainer  : phillip.harris@runtimeverification.com
Stability   : experimental
Portability : portable
-}

{-# LANGUAGE AllowAmbiguousTypes       #-}
{-# LANGUAGE ConstraintKinds           #-}
{-# LANGUAGE DeriveFoldable            #-}
{-# LANGUAGE DeriveFunctor             #-}
{-# LANGUAGE DeriveTraversable         #-}
{-# LANGUAGE FlexibleContexts          #-}
{-# LANGUAGE FunctionalDependencies    #-}
{-# LANGUAGE LambdaCase                #-}
{-# LANGUAGE MultiParamTypeClasses     #-}
{-# LANGUAGE NoMonomorphismRestriction #-}
{-# LANGUAGE PatternSynonyms           #-}
{-# LANGUAGE Rank2Types                #-}
{-# LANGUAGE TypeApplications          #-}
{-# LANGUAGE TypeFamilies              #-}

module Test.Data.Kore.Proof.Dummy where

import Data.Kore.AST.Common
import Data.Kore.AST.MetaOrObject
import Data.Kore.IndexedModule.MetadataTools
import Data.Reflection

import Data.Kore.ASTUtils.SmartConstructors

import Data.Kore.Proof.Proof

var :: MetaOrObject level => String -> Variable level
var x = x `varS` defaultSort

sym :: MetaOrObject level => String -> SymbolOrAlias level
sym x = x `symS` []

var_ :: MetaOrObject level => String -> String -> Variable level
var_ x s =
  Variable (noLocationId x) (mkSort s)

defaultSort :: MetaOrObject level => Sort level
defaultSort = mkSort "*"



dummyEnvironment
  :: forall r . MetaOrObject Object
  => (Given (MetadataTools Object) => r)
  -> r
dummyEnvironment = give (dummyMetadataTools @Object)

dummyMetadataTools
  :: MetaOrObject level
  => MetadataTools level
dummyMetadataTools = MetadataTools
    { isConstructor    = const True
    , isFunctional     = const True
    , isFunction       = const True
    , getArgumentSorts = const []
    , getResultSort    = const $ defaultSort
    }
