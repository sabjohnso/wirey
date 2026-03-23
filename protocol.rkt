#lang racket/base

(require wirey/field)

(provide make-protocol-desc
         protocol-desc?
         protocol-desc-name
         protocol-desc-fields
         protocol-desc-total-size
         protocol-desc-field-ref)

;; Internal struct
(struct protocol-desc (name fields) #:transparent)

;; Validated constructor
(define (make-protocol-desc name fields)
  (unless (symbol? name)
    (error 'make-protocol-desc "name must be a symbol, got: ~e" name))
  (unless (list? fields)
    (error 'make-protocol-desc "fields must be a list, got: ~e" fields))
  (for ([f (in-list fields)])
    (unless (field-desc? f)
      (error 'make-protocol-desc "each field must be a field-desc, got: ~e" f)))
  (protocol-desc name fields))

;; Sum of all field widths in bytes
(define (protocol-desc-total-size pd)
  (for/sum ([f (in-list (protocol-desc-fields pd))])
    (field-desc-width f)))

;; Lookup a field by name, or #f if not found
(define (protocol-desc-field-ref pd name)
  (for/first ([f (in-list (protocol-desc-fields pd))]
              #:when (eq? (field-desc-name f) name))
    f))
