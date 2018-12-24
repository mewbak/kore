branch: dev

[ ![Codeship Status for kframework/kore](https://app.codeship.com/projects/788a4510-bea7-0134-5644-0204b74559cb/status?branch=master)](https://app.codeship.com/projects/196330)

# The Kore Language

Kore is the "core" part of the K framework.

## What is Kore all about?

In short, we need a formal semantics of K.
In K, users can define formal syntax and semantics of
programming languages as K definitions, and automatically obtain
parsers, interpreters, compilers, and various verification tools
for their languages.
Therefore K is a language-independent framework.

Thanks to years of research in matching logic and reachability
logic, we know that all K does can be nicely formalized as
logic reasoning in matching logic.
To give K a formal semantics, we only need to formally specify
the underlying matching logic theories with which K does reasoning.
In practice, these underlying theories are complex and often
infinite, and it is tricky to specify infinite theories without
a carefully designed formal specification language.
And Kore is such a language.

## Structure of this project

The `/docs` directory contains a comprehensive document _Semantics of K_
that describes the mathematical foundation of Kore, and a BNF grammar
that defines the syntax of Kore language.

The `/src` directory contains a parser for the Kore language implemented
in scala.

The `/src/test` directory contains a collection of Kore definition examples.
