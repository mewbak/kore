{- |
Copyright   : (c) Runtime Verification, 2019
License     : NCSA

 -}

module Kore.Step.Remainder
    ( remainder, remainder'
    , existentiallyQuantifyTarget
    , ceilChildOfApplicationOrTop
    ) where

import Control.Applicative
    ( Alternative (..)
    )
import qualified Data.Foldable as Foldable

import Kore.Internal.Condition
    ( Condition
    )
import qualified Kore.Internal.Condition as Condition
import Kore.Internal.Conditional
    ( Conditional (Conditional)
    )
import Kore.Internal.MultiAnd
    ( MultiAnd
    )
import qualified Kore.Internal.MultiAnd as MultiAnd
import Kore.Internal.MultiOr
    ( MultiOr
    )
import qualified Kore.Internal.OrCondition as OrCondition
import Kore.Internal.Predicate
    ( Predicate
    )
import qualified Kore.Internal.Predicate as Predicate
import Kore.Internal.TermLike
import qualified Kore.Step.Simplification.AndPredicates as AndPredicates
import qualified Kore.Step.Simplification.Ceil as Ceil
import Kore.Step.Simplification.Simplify
    ( MonadSimplify (..)
    , SimplifierVariable
    )
import Kore.Unification.Substitution
    ( Substitution
    )
import qualified Kore.Unification.Substitution as Substitution
import Kore.Variables.Target
    ( Target
    )
import qualified Kore.Variables.Target as Target
import Kore.Variables.UnifiedVariable
    ( foldMapVariable
    )

{- | Negate the disjunction of unification solutions to form the /remainder/.

The /remainder/ is the parts of the initial configuration that is not matched
by any applied rule.

The resulting predicate has the 'Target' variables unwrapped.

See also: 'remainder\''

 -}
remainder
    :: InternalVariable variable
    => MultiOr (Condition (Target variable))
    -> Predicate variable
remainder =
    Predicate.mapVariables Target.unwrapVariable . remainder'

{- | Negate the disjunction of unification solutions to form the /remainder/.

The /remainder/ is the parts of the initial configuration that is not matched
by any applied rule.

 -}
remainder'
    :: InternalVariable variable
    => MultiOr (Condition (Target variable))
    -> Predicate (Target variable)
remainder' results =
    mkMultiAndPredicate $ mkNotExists conditions
  where
    conditions = mkMultiAndPredicate . unificationConditions <$> results
    mkNotExists = mkNotMultiOr . fmap existentiallyQuantifyTarget

-- | Existentially-quantify target (axiom) variables in the 'Condition'.
existentiallyQuantifyTarget
    :: InternalVariable variable
    => Predicate (Target variable)
    -> Predicate (Target variable)
existentiallyQuantifyTarget predicate =
    Predicate.makeMultipleExists freeTargetVariables predicate
  where
    freeTargetVariables =
        filter (Target.isTarget . getElementVariable)
        . Predicate.freeElementVariables
        $ predicate

{- | Negate a disjunction of many terms.

@
  ¬ (φ₁ ∨ φ₂ ∨ ...) = ¬φ₁ ∧ ¬φ₂ ∧ ...
@

 -}
mkNotMultiOr
    :: InternalVariable variable
    => MultiOr  (Predicate variable)
    -> MultiAnd (Predicate variable)
mkNotMultiOr =
    MultiAnd.make
    . map Predicate.makeNotPredicate
    . Foldable.toList

mkMultiAndPredicate
    :: InternalVariable variable
    => MultiAnd (Predicate variable)
    ->           Predicate variable
mkMultiAndPredicate =
    Predicate.makeMultipleAndPredicate . Foldable.toList

{- | Represent the unification solution as a conjunction of predicates.
 -}
unificationConditions
    :: InternalVariable variable
    => Condition (Target variable)
    -- ^ Unification solution
    -> MultiAnd (Predicate (Target variable))
unificationConditions Conditional { predicate, substitution } =
    pure predicate <|> substitutionConditions substitution'
  where
    substitution' =
        Substitution.filter (foldMapVariable Target.isNonTarget)
            substitution

substitutionConditions
    :: InternalVariable variable
    => Substitution variable
    -> MultiAnd (Predicate variable)
substitutionConditions subst =
    MultiAnd.make (substitutionCoverageWorker <$> Substitution.unwrap subst)
  where
    substitutionCoverageWorker (x, t) =
        Predicate.makeEqualsPredicate_ (mkVar x) t

ceilChildOfApplicationOrTop
    :: forall variable m
    .  (SimplifierVariable variable, MonadSimplify m)
    => Condition variable
    -> TermLike variable
    -> m (Condition variable)
ceilChildOfApplicationOrTop predicate patt =
    case patt of
        App_ _ children -> do
            ceil <-
                traverse (Ceil.makeEvaluateTerm predicate) children
                >>= ( AndPredicates.simplifyEvaluatedMultiPredicate
                    . MultiAnd.make
                    )
            pure $ Conditional
                { term = ()
                , predicate =
                    OrCondition.toPredicate
                    . fmap Condition.toPredicate
                    $ ceil
                , substitution = mempty
                }
        _ -> pure Condition.top
