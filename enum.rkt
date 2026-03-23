#lang racket/base

(require (for-syntax racket/base
                     syntax/parse))

(provide define-wire-enum
         wire-enum?
         wire-enum-ref
         wire-enum-lookup
         wire-enum-entries)

;; A wire-enum holds bidirectional mappings between symbols and integers.
(struct wire-enum (name sym->int int->sym entries) #:transparent)

;; Resolve a value for encoding: symbol → integer, integer → pass through
(define (wire-enum-ref we val)
  (if (symbol? val)
      (hash-ref (wire-enum-sym->int we) val
                (λ () (error 'wire-enum-ref
                             "unknown symbol '~a for enum ~a"
                             val (wire-enum-name we))))
      val))

;; Resolve a value for decoding: integer → symbol (if known), else integer
(define (wire-enum-lookup we val)
  (hash-ref (wire-enum-int->sym we) val val))

;; Macro to define a wire-enum
(define-syntax (define-wire-enum stx)
  (syntax-parse stx
    [(_ name:id [sym:id val:expr] ...)
     #'(define name
         (wire-enum 'name
                    (hasheq (~@ 'sym val) ...)
                    (hash (~@ val 'sym) ...)
                    (list (cons 'sym val) ...)))]))
