#lang racket/base

(require wirey/length-expr)

(provide field-type?
         byte-order?
         field-unit?
         make-field-desc
         field-desc?
         field-desc-name
         field-desc-type
         field-desc-width
         field-desc-byte-order
         field-desc-unit
         field-desc-compute
         field-desc-computed?
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

;; Types allowed for bitfields (bit-unit)
(define (bitfield-type? v)
  (memq v '(uint sint)))

;; Internal struct — 6th field is the optional compute function
(struct field-desc (name type width byte-order unit compute) #:transparent)

;; Validated constructor
(define (make-field-desc name type width byte-order
                         #:unit [unit 'bytes]
                         #:compute [compute-fn #f])
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
  (when (and (eq? unit 'bits) (not (bitfield-type? type)))
    (error 'make-field-desc
           "bit-unit fields must be uint or sint, got type: ~e" type))
  (when (and (eq? unit 'bits) (not (exact-positive-integer? width)))
    (error 'make-field-desc
           "bit-unit fields must have fixed width, got: ~e" width))
  (when (and compute-fn (not (procedure? compute-fn)))
    (error 'make-field-desc "#:compute must be a procedure, got: ~e" compute-fn))
  (field-desc name type width byte-order unit compute-fn))

;; Is this a computed field?
(define (field-desc-computed? fd)
  (and (field-desc-compute fd) #t))

;; Is this a variable-length field?
(define (field-desc-variable-length? fd)
  (not (exact-positive-integer? (field-desc-width fd))))

;; Width in bits regardless of unit (only valid for fixed-width fields)
(define (field-desc-width-in-bits fd)
  (define w (field-desc-width fd))
  (if (eq? (field-desc-unit fd) 'bits)
      w
      (* 8 w)))
