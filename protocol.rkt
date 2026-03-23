#lang racket/base

(require wirey/field
         wirey/length-expr)

(provide make-protocol-desc
         protocol-desc?
         protocol-desc-name
         protocol-desc-fields
         protocol-desc-total-size
         protocol-desc-field-ref
         protocol-desc-has-variable-fields?)

;; Internal struct
(struct protocol-desc (name fields) #:transparent)

;; Validate that contiguous bitfield groups sum to whole bytes.
(define (validate-bitfield-groups fields)
  (let loop ([fields fields] [bit-acc 0])
    (cond
      [(null? fields)
       (unless (zero? (remainder bit-acc 8))
         (error 'make-protocol-desc
                "bitfield group has ~a bits, which is not a whole number of bytes"
                bit-acc))]
      [(eq? (field-desc-unit (car fields)) 'bits)
       (loop (cdr fields) (+ bit-acc (field-desc-width (car fields))))]
      [else
       (unless (zero? (remainder bit-acc 8))
         (error 'make-protocol-desc
                "bitfield group has ~a bits, which is not a whole number of bytes"
                bit-acc))
       (loop (cdr fields) 0)])))

;; Validate that variable-length fields reference existing earlier fields.
(define (validate-variable-length-refs fields)
  (define seen '())
  (for ([f (in-list fields)])
    (define w (field-desc-width f))
    (when (field-ref? w)
      (define ref-name (field-ref-name w))
      (unless (memq ref-name seen)
        (error 'make-protocol-desc
               "field '~a' references '~a' which does not appear before it"
               (field-desc-name f) ref-name)))
    (when (compute? w)
      ;; For compute, we extract field-ref names from the source expression.
      ;; The compute function is opaque, so we validate at decode/encode time.
      ;; But we can do basic validation: check source for field-ref symbols.
      (validate-compute-refs (field-desc-name f) (compute-source w) seen))
    (set! seen (cons (field-desc-name f) seen))))

;; Walk the source expression of a compute to find (field-ref name) forms
;; and validate they reference earlier fields.
(define (validate-compute-refs field-name source seen)
  (cond
    [(and (pair? source) (eq? (car source) 'field-ref) (= (length source) 2))
     (define ref-name (cadr source))
     (unless (memq ref-name seen)
       (error 'make-protocol-desc
              "field '~a' compute references '~a' which does not appear before it"
              field-name ref-name))]
    [(pair? source)
     (for ([s (in-list source)])
       (validate-compute-refs field-name s seen))]
    [else (void)]))

;; Validated constructor
(define (make-protocol-desc name fields)
  (unless (symbol? name)
    (error 'make-protocol-desc "name must be a symbol, got: ~e" name))
  (unless (list? fields)
    (error 'make-protocol-desc "fields must be a list, got: ~e" fields))
  (for ([f (in-list fields)])
    (unless (field-desc? f)
      (error 'make-protocol-desc "each field must be a field-desc, got: ~e" f)))
  ;; Only validate bitfield groups for fixed-width fields
  (validate-bitfield-groups
   (filter (λ (f) (not (field-desc-variable-length? f))) fields))
  (validate-variable-length-refs fields)
  (protocol-desc name fields))

;; Sum of fixed field widths in bytes.
;; Variable-length fields are excluded (their size depends on data).
(define (protocol-desc-total-size pd)
  (let loop ([fields (protocol-desc-fields pd)] [bit-acc 0] [total 0])
    (cond
      [(null? fields)
       (+ total (quotient bit-acc 8))]
      [(field-desc-variable-length? (car fields))
       ;; Skip variable-length fields
       (define flush (if (zero? bit-acc) 0 (quotient bit-acc 8)))
       (loop (cdr fields) 0 (+ total flush))]
      [(eq? (field-desc-unit (car fields)) 'bits)
       (loop (cdr fields) (+ bit-acc (field-desc-width (car fields))) total)]
      [else
       (define flush (if (zero? bit-acc) 0 (quotient bit-acc 8)))
       (loop (cdr fields) 0 (+ total flush (field-desc-width (car fields))))])))

;; Does this protocol have any variable-length fields?
(define (protocol-desc-has-variable-fields? pd)
  (for/or ([f (in-list (protocol-desc-fields pd))])
    (field-desc-variable-length? f)))

;; Lookup a field by name, or #f if not found
(define (protocol-desc-field-ref pd name)
  (for/first ([f (in-list (protocol-desc-fields pd))]
              #:when (eq? (field-desc-name f) name))
    f))
