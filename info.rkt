#lang info
(define collection "wirey")
(define deps '("base"))
(define build-deps '("scribble-lib" "racket-doc" "rackunit-lib"))
(define scribblings '(("scribblings/wirey.scrbl" ())))
(define pkg-desc "Binary wire protocol specifications for Racket")
(define version "2.0.0")
(define pkg-authors '(sbj))
(define license '(Apache-2.0 OR MIT))
