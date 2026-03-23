#lang racket/base

(provide field-type?
         byte-order?
         make-field-desc
         field-desc?
         field-desc-name
         field-desc-type
         field-desc-width
         field-desc-byte-order)

;; Valid field types for v0.1: byte-aligned, fixed-width
(define (field-type? v)
  (and (symbol? v)
       (memq v '(uint sint alpha octets))
       #t))

;; Valid byte orderings
(define (byte-order? v)
  (and (symbol? v)
       (memq v '(big little))
       #t))

;; Internal struct — not exposed directly; use make-field-desc
(struct field-desc (name type width byte-order) #:transparent)

;; Validated constructor
(define (make-field-desc name type width byte-order)
  (unless (symbol? name)
    (error 'make-field-desc "name must be a symbol, got: ~e" name))
  (unless (field-type? type)
    (error 'make-field-desc "invalid field type: ~e" type))
  (unless (and (exact-positive-integer? width))
    (error 'make-field-desc "width must be a positive integer, got: ~e" width))
  (unless (byte-order? byte-order)
    (error 'make-field-desc "invalid byte-order: ~e" byte-order))
  (field-desc name type width byte-order))
