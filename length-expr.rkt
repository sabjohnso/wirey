#lang racket/base

(provide length-expr?
         fixed-length-expr?
         make-field-ref
         field-ref?
         field-ref-name
         make-compute
         compute?
         compute-source
         compute-fn
         eval-length-expr)

;; A length expression is one of:
;; - exact-positive-integer? (fixed width)
;; - field-ref (width = value of another field)
;; - compute (width = result of a function over field values)

(struct field-ref (name) #:transparent)
(struct compute (source fn) #:transparent)

(define (make-field-ref name)
  (unless (symbol? name)
    (error 'make-field-ref "name must be a symbol, got: ~e" name))
  (field-ref name))

(define (make-compute source fn)
  (compute source fn))

(define (length-expr? v)
  (or (exact-positive-integer? v)
      (field-ref? v)
      (compute? v)))

(define (fixed-length-expr? v)
  (exact-positive-integer? v))

;; Evaluate a length expression given a field lookup function.
;; lookup : symbol? -> any/c
(define (eval-length-expr expr lookup)
  (cond
    [(exact-positive-integer? expr) expr]
    [(field-ref? expr) (lookup (field-ref-name expr))]
    [(compute? expr) ((compute-fn expr) lookup)]))
