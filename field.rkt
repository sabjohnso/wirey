#lang racket/base

(require wirey/length-expr)

(provide field-type?
         byte-order?
         field-unit?
         bit-order?
         make-field-desc
         field-desc?
         field-desc-name
         field-desc-type
         field-desc-width
         field-desc-byte-order
         field-desc-unit
         field-desc-bit-order
         field-desc-compute
         field-desc-computed?
         field-desc-contract
         field-desc-has-contract?
         field-desc-width-in-bits
         field-desc-variable-length?)

;; Valid field types
(define (field-type? v)
  (and (symbol? v)
       (memq v '(uint sint alpha octets))
       #t))

;; Valid byte orderings
(define (byte-order? v)
  (and (symbol? v)
       (memq v '(big little))
       #t))

;; Valid width units
(define (field-unit? v)
  (and (symbol? v)
       (memq v '(bytes bits))
       #t))

;; Valid bit orderings
(define (bit-order? v)
  (and (symbol? v)
       (memq v '(msb lsb))
       #t))

;; Types allowed for bitfields (bit-unit)
(define (bitfield-type? v)
  (memq v '(uint sint)))

;; Internal struct — 8 fields
(struct field-desc (name type width byte-order unit bit-order compute contract)
  #:transparent)

;; Validated constructor
(define (make-field-desc name type width byte-order
                         #:unit [unit 'bytes]
                         #:bit-order [bit-ord #f]
                         #:compute [compute-fn #f]
                         #:contract [contract-fn #f])
  (unless (symbol? name)
    (error 'make-field-desc "name must be a symbol, got: ~e" name))
  (unless (field-type? type)
    (error 'make-field-desc "invalid field type: ~e" type))
  (unless (or (exact-positive-integer? width)
              (field-ref? width)
              (compute? width))
    (error 'make-field-desc "width must be a positive integer or length expression, got: ~e" width))
  (unless (byte-order? byte-order)
    (error 'make-field-desc "invalid byte-order: ~e" byte-order))
  (unless (field-unit? unit)
    (error 'make-field-desc "invalid unit: ~e" unit))
  (when (and bit-ord (not (bit-order? bit-ord)))
    (error 'make-field-desc "invalid bit-order: ~e" bit-ord))
  (when (and bit-ord (not (eq? unit 'bits)))
    (error 'make-field-desc
           "bit-order can only be specified on bit-unit fields, got unit: ~e" unit))
  (when (and (eq? unit 'bits) (not (bitfield-type? type)))
    (error 'make-field-desc
           "bit-unit fields must be uint or sint, got type: ~e" type))
  (when (and (eq? unit 'bits) (not (exact-positive-integer? width)))
    (error 'make-field-desc
           "bit-unit fields must have fixed width, got: ~e" width))
  (when (and compute-fn (not (procedure? compute-fn)))
    (error 'make-field-desc "#:compute must be a procedure, got: ~e" compute-fn))
  (when (and contract-fn (not (procedure? contract-fn)))
    (error 'make-field-desc "#:contract must be a procedure, got: ~e" contract-fn))
  (field-desc name type width byte-order unit bit-ord compute-fn contract-fn))

;; Is this a computed field?
(define (field-desc-computed? fd)
  (and (field-desc-compute fd) #t))

;; Does this field have a contract?
(define (field-desc-has-contract? fd)
  (and (field-desc-contract fd) #t))

;; Is this a variable-length field?
(define (field-desc-variable-length? fd)
  (not (exact-positive-integer? (field-desc-width fd))))

;; Width in bits regardless of unit (only valid for fixed-width fields)
(define (field-desc-width-in-bits fd)
  (define w (field-desc-width fd))
  (if (eq? (field-desc-unit fd) 'bits)
      w
      (* 8 w)))
